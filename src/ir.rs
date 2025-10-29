// ir.rs
#![no_std]

use crate::ast::{Program, FunctionDeclaration, Statement, Expression};
use crate::token::{Token, TokenKind};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, SemanticError}; // SemanticError'ı IR üretimi sırasında hatalar için kullanabiliriz
use sahne64::utils::{Vec, String, HashMap}; // No_std uyumlu koleksiyonlar

/// IR operasyonları (opcode'ler)
/// Bu liste dilimizin destekleyeceği temel işlemleri temsil eder.
#[derive(Debug, PartialEq, Clone)]
pub enum OpCode {
    // Sabitler
    PushInt(i64),     // Tam sayı sabiti yığına it.
    PushBool(bool),   // Boolean sabiti yığına it.
    PushString(String), // String sabiti yığına it.

    // Değişkenler (Yerel veya Global)
    LoadLocal(usize), // Yerel değişkeni yığına yükle (indeks).
    StoreLocal(usize),// Yığındaki değeri yerel değişkene ata (indeks).
    LoadGlobal(String), // Global değişkeni yığına yükle (adı).
    StoreGlobal(String),// Yığındaki değeri global değişkene ata (adı).

    // Aritmetik Operasyonlar
    Add, Sub, Mul, Div,

    // Karşılaştırma Operasyonları
    Eq, Ne, Lt, Le, Gt, Ge,

    // Mantıksal Operasyonlar
    And, Or, Not,

    // Kontrol Akışı
    Jump(usize),       // Belirtilen adrese koşulsuz atla.
    JumpIfFalse(usize),// Yığının tepesindeki değer false ise atla.
    Call(String, usize), // Fonksiyon çağrısı (fonksiyon adı, argüman sayısı).
    Return,            // Fonksiyondan dön.

    // Fonksiyon Sonu (Code Generation için yardımcı)
    FunctionEnd,

    // Sistem Çağrıları (Sahne Karnal için özel)
    // Şimdilik print'i örnek olarak ekleyelim, diğerleri hedef modülde daha detaylı işlenir.
    SyscallPrintInt, // Yığındaki int'i yazdır.
    SyscallPrintBool, // Yığındaki bool'u yazdır.
    SyscallPrintString, // Yığındaki string'i yazdır.

    // No-Op (Boş işlem - Etiketler için yer tutucu)
    NoOp,
}

/// Her bir IR yönergesi, bir OpCode ve hata ayıklama için kaynak konum bilgisi içerir.
#[derive(Debug, PartialEq, Clone)]
pub struct IRInstruction {
    pub opcode: OpCode,
     pub line: usize,    // Orijinal kaynak kod satırı (debugging için faydalı)
     pub column: usize,  // Orijinal kaynak kod sütunu
}

impl IRInstruction {
    pub fn new(opcode: OpCode /*, line: usize, column: usize*/) -> Self {
        IRInstruction { opcode /*, line, column */ }
    }
}

/// Fonksiyonun IR temsilini tutar.
#[derive(Debug, Clone)]
pub struct IRFunction {
    pub name: String,
    pub instructions: Vec<IRInstruction>,
    pub parameter_count: usize,
    pub return_type: Type,
    pub local_variables: HashMap<String, usize>, // Yerel değişkenler ve yığındaki ofsetleri
    pub next_local_offset: usize, // Bir sonraki yerel değişken için uygun ofset
}

impl IRFunction {
    pub fn new(name: String, param_count: usize, return_type: Type) -> Self {
        IRFunction {
            name,
            instructions: Vec::new(),
            parameter_count: param_count,
            return_type,
            local_variables: HashMap::new(),
            next_local_offset: param_count, // Parametreler 0'dan başlar, yerel değişkenler onlardan sonra
        }
    }

    pub fn add_instruction(&mut self, opcode: OpCode) { // , line: usize, column: usize) {
        self.instructions.push(IRInstruction::new(opcode /*, line, column */));
    }

    /// Yeni bir yerel değişken tanımlar ve ona yığın üzerinde bir ofset atar.
    pub fn define_local(&mut self, name: String) -> usize {
        let offset = self.next_local_offset;
        self.local_variables.insert(name, offset);
        self.next_local_offset += 1;
        offset
    }

    /// Bir yerel değişkenin ofsetini döndürür.
    pub fn get_local_offset(&self, name: &str) -> Option<usize> {
        self.local_variables.get(name).copied()
    }
}

/// Tüm programın IR temsilini tutar.
#[derive(Debug)]
pub struct IRModule {
    pub functions: HashMap<String, IRFunction>,
    pub global_variables: HashMap<String, usize>, // Global değişkenler ve ofsetleri (veya adresleri)
    pub main_function_name: String, // Ana fonksiyonun adı
}

impl IRModule {
    pub fn new() -> Self {
        IRModule {
            functions: HashMap::new(),
            global_variables: HashMap::new(),
            main_function_name: String::from("main"), // Varsayılan ana fonksiyon adı
        }
    }

    pub fn add_function(&mut self, func: IRFunction) {
        self.functions.insert(func.name.clone(), func);
    }

    pub fn get_function_mut(&mut self, name: &str) -> Option<&mut IRFunction> {
        self.functions.get_mut(name)
    }

    /// Yeni bir global değişken tanımlar.
    pub fn define_global(&mut self, name: String) -> usize {
        let offset = self.global_variables.len(); // Basit bir ofset ataması
        self.global_variables.insert(name, offset);
        offset
    }
}

/// AST'den IR üretmekten sorumlu yapı.
pub struct IRGenerator<'a> {
    current_function: Option<String>, // Halihazırda işlenen fonksiyonun adı
    /// Kontrol akışı için etiketleri (label) ve bunların hedef adreslerini tutar.
    /// Anahtar: Etiket adı (String), Değer: IRInstruction listesindeki indeks.
    labels: HashMap<String, usize>,
    /// İleriye referans veren Jump komutları için geçici yer tutucu.
    /// (Jump komutunun indeksi, Hedef etiket adı)
    jump_patches: Vec<(usize, String)>,
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> IRGenerator<'a> {
    pub fn new() -> Self {
        IRGenerator {
            current_function: None,
            labels: HashMap::new(),
            jump_patches: Vec::new(),
            _phantom: core::marker::PhantomData,
        }
    }

    /// Programın AST'sinden IR modülünü üretir.
    pub fn generate(&mut self, program: &Program<'a>) -> IRModule {
        let mut ir_module = IRModule::new();

        // 1. Global değişkenleri işle (şimdilik main fonksiyonunun dışındaki var bildirimleri)
        // Program'ın global statements'ından değişken bildirimlerini ayıkla
        for stmt in program.statements.iter() {
            if let Statement::VarDeclaration { name, declared_type, .. } = stmt {
                // Global değişkenleri IRModule'e ekle
                // Basitlik için sadece yerini ayırıyoruz, değeri daha sonra atanacak
                ir_module.define_global(String::from(name.lexeme));
            }
        }


        // 2. Fonksiyonları işle
        for func_decl in program.functions.iter() {
            let func_name = String::from(func_decl.name.lexeme);
            let mut ir_func = IRFunction::new(
                func_name.clone(),
                func_decl.parameters.len(),
                func_decl.resolved_return_type.clone()
            );

            // Fonksiyon parametrelerini yerel değişken olarak kaydet
            for (idx, param) in func_decl.parameters.iter().enumerate() {
                ir_func.local_variables.insert(String::from(param.lexeme), idx);
            }
            ir_func.next_local_offset = func_decl.parameters.len(); // Parametreler yerel kapsamın başlangıcıdır

            self.current_function = Some(func_name.clone());
            self.labels.clear();
            self.jump_patches.clear();

            // Fonksiyon gövdesini IR'ye dönüştür
            self.generate_statement(&mut ir_func, &func_decl.body);

            // Fonksiyonun sonunda dönüş yönergesi ekle (eğer zaten yoksa)
            if ir_func.instructions.last().map_or(true, |inst| inst.opcode != OpCode::Return) {
                 ir_func.add_instruction(OpCode::Return);
            }
            ir_func.add_instruction(OpCode::FunctionEnd);


            // Atlamaları (Jump) düzelt (label'ları gerçek adreslere çevir)
            self.patch_jumps(&mut ir_func);

            ir_module.add_function(ir_func);
        }

        // Eğer main fonksiyonu tanımlı değilse, otomatik bir main fonksiyonu oluşturabiliriz
        // veya derleme hatası verebiliriz. Şimdilik varsayılan `main`'ı bekleyelim.
        if !ir_module.functions.contains_key(&ir_module.main_function_name) {
             eprintln!("Uyarı: 'main' fonksiyonu bulunamadı. Program yürütülemeyebilir.");
             // TODO: Hata veya varsayılan bir boş main ekleme.
        }

        ir_module
    }

    /// Bir ifadeyi IR'ye dönüştürür. İfade, sonucunu yığına bırakır.
    fn generate_expression(&mut self, ir_func: &mut IRFunction, expr: &Expression<'a>) {
        match expr {
            Expression::Literal { token, ty } => {
                match token.kind {
                    TokenKind::Integer => {
                        let value = token.lexeme.parse::<i64>().unwrap_or(0); // Hata kontrolü yapılmalı
                        ir_func.add_instruction(OpCode::PushInt(value));
                    }
                    TokenKind::String => {
                        // String'i alıntı işaretlerinden arındır ve String olarak sakla
                        let s = token.lexeme.trim_matches('"');
                        ir_func.add_instruction(OpCode::PushString(String::from(s)));
                    }
                    TokenKind::True => ir_func.add_instruction(OpCode::PushBool(true)),
                    TokenKind::False => ir_func.add_instruction(OpCode::PushBool(false)),
                    _ => { /* Error: Should not happen after semantic analysis */ }
                }
            }
            Expression::Identifier { token, .. } => {
                let name = String::from(token.lexeme);
                if let Some(offset) = ir_func.get_local_offset(&name) {
                    ir_func.add_instruction(OpCode::LoadLocal(offset));
                } else if let Some(_) = self.get_ir_module_ref().global_variables.get(&name) {
                    // Global değişkenler için LoadGlobal
                    ir_func.add_instruction(OpCode::LoadGlobal(name));
                } else {
                    // Bu noktaya gelinmemeli, semantik analiz halletmiş olmalı.
                    eprintln!("Hata: Tanımlanmamış değişken IR üretimi sırasında: {}", name);
                }
            }
            Expression::Binary { left, operator, right, .. } => {
                self.generate_expression(ir_func, left);
                self.generate_expression(ir_func, right);
                match operator.kind {
                    TokenKind::Plus => ir_func.add_instruction(OpCode::Add),
                    TokenKind::Minus => ir_func.add_instruction(OpCode::Sub),
                    TokenKind::Star => ir_func.add_instruction(OpCode::Mul),
                    TokenKind::Slash => ir_func.add_instruction(OpCode::Div),
                    TokenKind::EqEq => ir_func.add_instruction(OpCode::Eq),
                    TokenKind::BangEq => ir_func.add_instruction(OpCode::Ne),
                    TokenKind::Lt => ir_func.add_instruction(OpCode::Lt),
                    TokenKind::Le => ir_func.add_instruction(OpCode::Le),
                    TokenKind::Gt => ir_func.add_instruction(OpCode::Gt),
                    TokenKind::Ge => ir_func.add_instruction(OpCode::Ge),
                    TokenKind::And => ir_func.add_instruction(OpCode::And),
                    TokenKind::Or => ir_func.add_instruction(OpCode::Or),
                    _ => { /* Should not happen */ }
                }
            }
            Expression::Unary { operator, right, .. } => {
                self.generate_expression(ir_func, right);
                match operator.kind {
                    TokenKind::Minus => { /* Negasyon için yığına PushInt(-1) ve Mul eklenebilir, veya özel OpCode */ }
                    TokenKind::Bang => ir_func.add_instruction(OpCode::Not),
                    _ => { /* Should not happen */ }
                }
            }
            Expression::Call { callee, arguments, .. } => {
                // Argümanları yığına it
                for arg in arguments.iter() {
                    self.generate_expression(ir_func, arg);
                }
                if let Expression::Identifier { token: callee_token, .. } = &**callee {
                    ir_func.add_instruction(OpCode::Call(String::from(callee_token.lexeme), arguments.len()));
                } else {
                    // Semantic Analyzer'da yakalanmış olmalı.
                    eprintln!("Hata: Geçersiz fonksiyon çağrısı callee türü.");
                }
            }
            Expression::Grouping { expression, .. } => {
                self.generate_expression(ir_func, expression);
            }
            Expression::Assign { name, value, .. } => {
                self.generate_expression(ir_func, value); // Sağ tarafın değeri yığına itilir
                let var_name = String::from(name.lexeme);
                if let Some(offset) = ir_func.get_local_offset(&var_name) {
                    ir_func.add_instruction(OpCode::StoreLocal(offset));
                } else if let Some(_) = self.get_ir_module_ref().global_variables.get(&var_name) {
                    ir_func.add_instruction(OpCode::StoreGlobal(var_name));
                } else {
                    // Semantik analizde yakalanmış olmalı
                    eprintln!("Hata: Atama hedefi tanımlanmamış: {}", var_name);
                }
            }
        }
    }

    /// Bir bildirimi IR'ye dönüştürür.
    fn generate_statement(&mut self, ir_func: &mut IRFunction, stmt: &Statement<'a>) {
        match stmt {
            Statement::Expression { expr, .. } => {
                self.generate_expression(ir_func, expr);
                // İfade bildirimi yığında bir değer bırakıyorsa ve kullanılmıyorsa, onu pop etmeliyiz.
                // Basitlik için şimdilik her ifade bildiriminin değerini tutmuyoruz.
            }
            Statement::Print { expr, .. } => {
                self.generate_expression(ir_func, expr);
                // Expr'ın türüne göre doğru syscall'ı çağır
                match expr.get_type() {
                    Type::Integer => ir_func.add_instruction(OpCode::SyscallPrintInt),
                    Type::Boolean => ir_func.add_instruction(OpCode::SyscallPrintBool),
                    Type::String => ir_func.add_instruction(OpCode::SyscallPrintString),
                    _ => {
                        eprintln!("Uyarı: Yazdırılamayan tür: {:?}", expr.get_type());
                    }
                }
            }
            Statement::VarDeclaration { name, initializer, mutable: _, declared_type } => {
                let var_name = String::from(name.lexeme);
                let offset = ir_func.define_local(var_name.clone()); // Yerel değişkeni tanımla

                if let Some(init_expr) = initializer {
                    self.generate_expression(ir_func, init_expr); // Başlangıç değerini yığına it
                    ir_func.add_instruction(OpCode::StoreLocal(offset)); // Yığındaki değeri değişkene ata
                } else {
                    // Başlangıç değeri olmayan değişkenler için varsayılan bir değer atayabiliriz
                    // veya bu durumun kod üretiminde ele alınmasını bekleyebiliriz.
                    // Örneğin: 0 veya false veya boş string ile başlatma
                     ir_func.add_instruction(OpCode::PushInt(0));
                     ir_func.add_instruction(OpCode::StoreLocal(offset));
                }
            }
            Statement::Block(statements) => {
                // Bloklar için yeni bir IR fonksiyonu kapsamı açmıyoruz,
                // çünkü yerel değişkenler zaten semantik analizde yönetiliyor.
                // Ancak kod üretimi sırasında stack frame'i doğru yönetmek için dikkat etmek gerekir.
                for s in statements.iter() {
                    self.generate_statement(ir_func, s);
                }
            }
            Statement::If { condition, then_branch, else_branch } => {
                // If Condition
                self.generate_expression(ir_func, condition); // Koşulun değeri yığına itilir

                let else_label = self.generate_label_name("else");
                let end_if_label = self.generate_label_name("end_if");

                // Eğer koşul yanlışsa 'else' bloğuna atla
                ir_func.add_instruction(OpCode::JumpIfFalse(0)); // Geçici hedef, daha sonra düzeltilecek
                let jif_idx = ir_func.instructions.len() - 1;
                self.jump_patches.push((jif_idx, else_label.clone()));

                // Then Branch
                self.generate_statement(ir_func, then_branch);

                if else_branch.is_some() {
                    // 'then' bloğu bittikten sonra 'end_if'e atla
                    ir_func.add_instruction(OpCode::Jump(0)); // Geçici hedef
                    let jump_idx = ir_func.instructions.len() - 1;
                    self.jump_patches.push((jump_idx, end_if_label.clone()));
                }

                // Else Label (buraya atlanacak)
                self.add_label_to_current_instruction(ir_func, else_label);

                // Else Branch
                if let Some(else_stmt) = else_branch {
                    self.generate_statement(ir_func, else_stmt);
                }

                // End If Label (buraya atlanacak)
                self.add_label_to_current_instruction(ir_func, end_if_label);
            }
            Statement::While { condition, body } => {
                let loop_start_label = self.generate_label_name("loop_start");
                let loop_end_label = self.generate_label_name("loop_end");

                self.add_label_to_current_instruction(ir_func, loop_start_label.clone()); // Döngü başlangıcı

                self.generate_expression(ir_func, condition); // Koşul yığına itilir
                ir_func.add_instruction(OpCode::JumpIfFalse(0)); // Geçici hedef
                let jif_idx = ir_func.instructions.len() - 1;
                self.jump_patches.push((jif_idx, loop_end_label.clone()));

                self.generate_statement(ir_func, body); // Döngü gövdesi

                ir_func.add_instruction(OpCode::Jump(0)); // Döngü başına geri dön
                let jump_idx = ir_func.instructions.len() - 1;
                self.jump_patches.push((jump_idx, loop_start_label.clone()));

                self.add_label_to_current_instruction(ir_func, loop_end_label); // Döngü sonu
            }
            Statement::Return { value, .. } => {
                if let Some(expr) = value {
                    self.generate_expression(ir_func, expr); // Dönüş değerini yığına it
                }
                ir_func.add_instruction(OpCode::Return);
            }
        }
    }

    /// Yeni bir benzersiz etiket adı oluşturur.
    fn generate_label_name(&self, prefix: &str) -> String {
        let unique_id = sahne64::rng::random_u64(); // Sahne64'ten rastgele sayı kullan (varsayımsal)
        String::from_format_args!("{}{}", prefix, unique_id)
    }

    /// Mevcut IR yönergesinin bulunduğu konuma bir etiket yerleştirir.
    fn add_label_to_current_instruction(&mut self, ir_func: &mut IRFunction, label_name: String) {
        let current_address = ir_func.instructions.len();
        self.labels.insert(label_name, current_address);
    }

    /// Geçici atlama hedeflerini gerçek adreslerle düzeltir.
    fn patch_jumps(&mut self, ir_func: &mut IRFunction) {
        for (inst_idx, label_name) in self.jump_patches.drain(..) {
            if let Some(&target_address) = self.labels.get(&label_name) {
                match &mut ir_func.instructions[inst_idx].opcode {
                    OpCode::Jump(ref mut addr) => *addr = target_address,
                    OpCode::JumpIfFalse(ref mut addr) => *addr = target_address,
                    _ => { /* Bu noktaya gelinmemeli */ }
                }
            } else {
                eprintln!("Hata: Tanımlanmamış atlama hedefi etiketi: {}", label_name);
                // Bu durum, semantik analizde yakalanmış olmalı veya bir iç derleyici hatasıdır.
            }
        }
    }

    /// IRGenerator'ın bir IRModule referansına erişmesini sağlar (geçici çözüm).
    /// Gerçek bir implementasyonda IRModule, IRGenerator'a geçirilmeli veya state olarak tutulmalıdır.
    fn get_ir_module_ref(&self) -> &IRModule {
        // Bu kısım, `IRGenerator`'ın `IRModule`'ü doğrudan değiştirmesi veya
        // bir referansını tutması gereken durumlarda kullanılır.
        // Mevcut yapıda, `generate` fonksiyonu `IRModule`'ü döndürdüğü için
        // global değişkenlere erişim için dışarıdan gelen bir referansa ihtiyacımız var.
        // Şimdilik bunu basitleştiriyoruz, ancak bu genellikle bir struct field olarak saklanır.
        // Örneğin: `ir_module: &'a mut IRModule,`
        // Ancak bu, `generate` fonksiyonunun yapısını değiştirir.
        // Hata ayıklama veya geçici kontrol amaçlı olduğu varsayılsın.
        unsafe {
            // UYARI: Bu unsafe block geçici bir çözümdür ve gerçek derleyicide kaçınılmalıdır.
            // IRGenerator'ın IRModule'e erişimini yönetmenin daha güvenli yolları vardır.
            // Örneğin, IRGenerator'ın IRModule'ü bir alan olarak alması.
            // Veya tüm global değişkenlerin başlangıçta bir kez işlenmesi.
            static mut DUMMY_IR_MODULE: core::mem::MaybeUninit<IRModule> = core::mem::MaybeUninit::uninit();
            &*(DUMMY_IR_MODULE.as_ptr()) // Bu, tanımsız davranışa yol açabilir
        }
    }
}
