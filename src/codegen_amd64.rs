// codegen_x86_64.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// x86_64 mimarisi için kod üreticisi
pub struct X86_64CodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    /// IRGenerator'daki patch mekanizması burada da uygulanacak.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl X86_64CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        X86_64CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den x86_64 assembly kodu üretir.
    pub fn generate_assembly(&mut self, ir_module: &IRModule) -> Result<String> {
        self.output_assembly.clear();
        self.string_literals.clear();
        self.next_string_id = 0;
        self.global_variable_addresses.clear();

        self.emit_prelude();

        // 1. Global değişkenleri ve string sabitlerini işle
        self.emit_data_section(ir_module)?;

        // 2. Fonksiyonları işle
        for func in ir_module.functions.values() {
            self.generate_x86_64_function(func)?;
        }

        self.emit_postlude();

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (.data, .text bölümleri vb.)
    fn emit_prelude(&mut self) {
        self.emit_line(".section .data");
        self.emit_line(".align 8"); // 8-bayt hizalama (veri için)
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        // Genellikle x86_64'te özel bir postlude gerekmeyebilir.
    }

    /// Veri bölümünü (global değişkenler, string sabitleri) üretir.
    fn emit_data_section(&mut self, ir_module: &IRModule) -> Result<()> {
        // String sabitlerini topla ve etiketlerini oluştur
        for func in ir_module.functions.values() {
            for inst in func.instructions.iter() {
                if let OpCode::PushString(s) = &inst.opcode {
                    if !self.string_literals.contains_key(s) {
                        let label = String::from_format_args!("__str_{}", self.next_string_id);
                        self.next_string_id += 1;
                        self.string_literals.insert(s.clone(), label.clone());
                        self.emit_line(&format!("{}:", label));
                        // x86_64'te stringler için .asciz (ASCII string, null-terminated)
                        self.emit_line(&format!("  .asciz \"{}\"", s));
                    }
                }
            }
        }
        // Global değişkenler için yer ayır
        for (name, _offset) in ir_module.global_variables.iter() {
            let label = String::from_format_args!("__{}_global", name); // Global değişken için etiket
            self.global_variable_addresses.insert(name.clone(), label.clone());
            self.emit_line(&format!("{}:", label));
            self.emit_line("  .quad 0"); // 64-bit sıfır değeriyle başlat (8 bayt)
            self.emit_line(".align 8"); // 8-bayt hizalama
        }

        self.emit_line(".section .text");
        self.emit_line(".align 16"); // Fonksiyonlar için 16-bayt hizalama
        Ok(())
    }

    /// Tek bir fonksiyonun x86_64 assembly kodunu üretir.
    fn generate_x86_64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".globl {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".type {}, @function", func_name)); // Fonksiyon tipini belirt
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // rbp'yi stack'e it ve rbp'yi rsp'ye ayarla
        self.emit_line("  pushq %rbp");      // rbp'yi stack'e kaydet
        self.emit_line("  movq %rsp, %rbp"); // rbp'yi mevcut rsp'ye ayarla

        // Yerel değişkenler için yığın alanı ayır
        // Her değişken için 8 bayt yer varsayalım (64-bit)
        let mut local_vars_size = func.next_local_offset * 8;
        // Stack'in 16 bayt hizalı olması için ek boşluk
        if local_vars_size % 16 != 0 {
            local_vars_size = (local_vars_size / 16 + 1) * 16;
        }
        if local_vars_size > 0 {
            self.emit_line(&format!("  subq ${}, %rsp", local_vars_size));
        }

        // Parametreleri yerel değişken ofsetlerine kopyala
        // x86_64 çağrı kuralı (System V ABI):
        // rdi, rsi, rdx, rcx, r8, r9 ilk 6 argüman için kullanılır.
        let arg_regs = ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"];
        for i in 0..func.parameter_count {
            if i < arg_regs.len() {
                let arg_reg = arg_regs[i];
                // Yerel değişken ofseti: rbp'ye göre negatif ofset
                // (parametreler, yerel değişken alanı içindeki en düşük adreslerden başlar)
                let offset_from_rbp = (i * 8) as isize - local_vars_size as isize;
                self.emit_line(&format!("  movq {}, {}(%rbp)", arg_reg, offset_from_rbp));
            } else {
                // Kalan argümanlar stack'ten alınır.
                // call yönergesi dönüş adresini ittiği için, rbp+16'dan başlar.
                let stack_arg_offset = (i - arg_regs.len() + 2) * 8; // rbp+8 (eski rbp) + 8 (return addr)
                let offset_from_rbp = stack_arg_offset as isize;
                self.emit_line(&format!("  movq {}(%rbp), %rax", offset_from_rbp)); // Argümanı rax'a al
                self.emit_line(&format!("  movq %rax, {}(%rbp)", (i * 8) as isize - local_vars_size as isize)); // Sonra yerel değişken konumuna taşı
            }
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            // Her yönerge için bir etiket tanımla (Jump hedefleri için)
            // IRGenerator'daki etiket düzeltme mekanizmasının burada da uygulanması gerekiyor.
            // IRInstruction'ların indeksleri etiket olarak kullanılabilir.
            self.emit_line(&format!(".L_{}_{}:", func_name, i));

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  pushq ${}", val)); // Integer'ı stack'e it
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  pushq ${}", bool_val)); // Boolean'ı stack'e it
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        self.emit_line(&format!("  leaq {}(%rip), %rax", label)); // String etiketinin adresini rax'a yükle (rip-relative)
                        self.emit_line("  pushq %rax"); // rax'ı stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    let offset_from_rbp = (offset * 8) as isize - local_vars_size as isize;
                    self.emit_line(&format!("  pushq {}(%rbp)", offset_from_rbp)); // Yerel değişkeni stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  popq %rax"); // Stack'ten değeri rax'a al
                    let offset_from_rbp = (offset * 8) as isize - local_vars_size as isize;
                    self.emit_line(&format!("  movq %rax, {}(%rbp)", offset_from_rbp)); // rax'ı yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  movq {}(%rip), %rax", label)); // Global değişkenin değerini rax'a yükle (rip-relative)
                        self.emit_line("  pushq %rax"); // rax'ı stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  popq %rax"); // Stack'ten değeri rax'a al
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  movq %rax, {}(%rip)", label)); // rax'ı global değişkene kaydet (rip-relative)
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_x86_64_binary_op("addq"),
                OpCode::Sub => self.emit_x86_64_binary_op("subq"),
                OpCode::Mul => {
                    // x86_64'te `mulq` tek argüman alır (rax ile çarpılır).
                    // İki operandı stack'ten al, birini rax'a, diğerini rbx'e koy.
                    self.emit_line("  popq %rbx"); // Sağ operandı rbx'e
                    self.emit_line("  popq %rax"); // Sol operandı rax'a
                    self.emit_line("  imulq %rbx"); // rax = rax * rbx
                    self.emit_line("  pushq %rax"); // Sonucu stack'e it
                }
                OpCode::Div => {
                    // x86_64'te `idivq` tek argüman alır (rax'ı böler).
                    // rax'ı sign-extend etmek için `cqo` kullanılır.
                    self.emit_line("  popq %rbx"); // Bölen (divisor) rbx'e
                    self.emit_line("  popq %rax"); // Bölünen (dividend) rax'a
                    self.emit_line("  cqo");       // rax'ı rdx:rax'a genişlet (sign-extend rax into rdx)
                    self.emit_line("  idivq %rbx"); // rax = rdx:rax / rbx, rdx = kalan
                    self.emit_line("  pushq %rax"); // Bölüm sonucunu stack'e it
                }
                OpCode::Eq => self.emit_x86_64_comparison_op("je"), // Eşitse 1, değilse 0
                OpCode::Ne => self.emit_x86_64_comparison_op("jne"),
                OpCode::Lt => self.emit_x86_64_comparison_op("jl"),
                OpCode::Le => self.emit_x86_64_comparison_op("jle"),
                OpCode::Gt => self.emit_x86_64_comparison_op("jg"),
                OpCode::Ge => self.emit_x86_64_comparison_op("jge"),
                OpCode::And => self.emit_x86_64_binary_op("andq"),
                OpCode::Or => self.emit_x86_64_binary_op("orq"),
                OpCode::Not => {
                    self.emit_line("  popq %rax");      // Değeri rax'a al
                    self.emit_line("  cmpq $0, %rax"); // rax'ı 0 ile karşılaştır
                    self.emit_line("  sete %al");       // Eşitse al=1, değilse al=0
                    self.emit_line("  movzbq %al, %rax"); // al'daki 1 baytı rax'a sıfırla doldurarak taşı
                    self.emit_line("  pushq %rax");     // Sonucu stack'e it
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  jmp .L_{}_{}", func_name, target_idx));
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  popq %rax");      // Koşulu rax'a al
                    self.emit_line("  cmpq $0, %rax"); // rax'ı 0 ile karşılaştır
                    self.emit_line(&format!("  je .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından registerlara yükle (sağdan sola)
                    // x86_64 ABI: rdi, rsi, rdx, rcx, r8, r9
                    let mut current_arg_regs = Vec::new();
                    for i in 0..*arg_count {
                        if i < arg_regs.len() {
                            current_arg_regs.push(arg_regs[i]);
                        } else {
                            // Stack'ten argüman geçirme (burada karmaşıklaşır)
                            // Şimdilik sadece ilk 6 argümanı destekleyelim.
                            eprintln!("Uyarı: x86_64'te 6'dan fazla argüman şu an desteklenmiyor.");
                        }
                    }

                    // Argümanları ters sırada registerlara taşı
                    for (i, reg) in current_arg_regs.iter().rev().enumerate() {
                        self.emit_line(&format!("  popq {}", reg)); // Stack'ten pop et ve registera taşı
                    }

                    // Stack hizalamasını korumak için gerekirse %rsp'yi ayarla
                    // Eğer argüman sayısı tek ise (push edilen toplam bayt tekse), bir boş push/sub yaparız.
                    // Her argüman 8 bayt. Toplam pop edilen argüman boyutu: arg_count * 8
                    let stack_adjustment = (arg_count * 8) % 16;
                    if stack_adjustment != 0 {
                         // Eğer call'dan sonra rsp 16'nın katı olmayacaksa (yani (toplam_pop + 8) % 16 != 0 ise)
                         // 8 baytlık bir boşluk bırakırız.
                         // call yönergesi zaten 8 bayt iteceği için, ek 8 bayt daha azaltırız.
                         self.emit_line("  subq $8, %rsp"); // 16-bayt hizalama için ek boşluk
                    }


                    self.emit_line(&format!("  call {}", callee_name)); // Fonksiyonu çağır

                    // Stack hizalamasını geri al
                    if stack_adjustment != 0 {
                        self.emit_line("  addq $8, %rsp");
                    }

                    // Dönüş değeri rax'ta olur, onu yığına it
                    self.emit_line("  pushq %rax");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa rax'a yükle (yığının tepesinden)
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  popq %rax"); // Stack'ten değeri rax'a al
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    self.emit_line("  movq %rbp, %rsp"); // rsp'yi rbp'ye geri getir (yerel değişken alanını serbest bırak)
                    self.emit_line("  popq %rbp");       // Eski rbp'yi stack'ten geri yükle
                    self.emit_line("  ret");             // Fonksiyondan dön
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_x86_64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_x86_64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_x86_64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// x86_64 için ikili operatör kodu üretir.
    fn emit_x86_64_binary_op(&mut self, instruction: &str) {
        self.emit_line("  popq %rbx"); // Sağ operandı rbx'e yükle
        self.emit_line("  popq %rax"); // Sol operandı rax'a yükle
        self.emit_line(&format!("  {} %rbx, %rax", instruction)); // İşlemi yap (rax = rax op rbx)
        self.emit_line("  pushq %rax"); // Sonucu stack'e it
    }

    /// x86_64 için karşılaştırma operatörü kodu üretir.
    fn emit_x86_64_comparison_op(&mut self, jump_instruction: &str) {
        self.emit_line("  popq %rbx"); // Sağ operandı rbx'e
        self.emit_line("  popq %rax"); // Sol operandı rax'a
        self.emit_line("  cmpq %rbx, %rax"); // rax ile rbx'i karşılaştır (rax - rbx)

        // Koşullu atlama ile boolean değeri üretme
        let true_label = String::from_format_args!(".L_true_{}", self.next_string_id);
        let end_label = String::from_format_args!(".L_end_{}", self.next_string_id);
        self.next_string_id += 1; // Benzersiz etiketler için

        self.emit_line(&format!("  {} {}", jump_instruction, true_label)); // Koşul doğruysa true_label'a atla
        self.emit_line("  pushq $0"); // False ise 0'ı it
        self.emit_line(&format!("  jmp {}", end_label)); // End_label'a atla
        self.emit_line(&format!("{}:", true_label));
        self.emit_line("  pushq $1"); // True ise 1'i it
        self.emit_line(&format!("{}:", end_label));
    }


    /// x86_64 için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_x86_64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  popq %rdi"); // Yığından değeri rdi'ye yükle (argüman 1: buffer/value)

        let syscall_num = 1; // `write` syscall numarası (Linux x86_64 ABI'ye göre)

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                // write syscall: rdi=fd (1 for stdout), rsi=buf, rdx=count
                // Sayı ve boolean için: Sayıyı bir string'e çevirmek ve sonra yazmak gerekir.
                // Bu kısım karmaşık ve runtime desteği ister.
                // Şimdilik sadece rdi'deki değeri varsayılan olarak yazdırdığını varsayalım.
                self.emit_line("  movq $1, %rax"); // Syscall numarası (write)
                self.emit_line("  movq $1, %rdi"); // stdout (fd=1)
                self.emit_line("  movq %rdi, %rsi"); // rdi'deki değeri rsi'ye taşı (buf - değerin kendisi)
                self.emit_line("  movq $8, %rdx"); // 8 bayt yazdır (long size, varsayımsal)
                                                  // NOTE: Integer/Boolean için, sayıyı string'e çevirmesi gerekir
                                                  // Bu basitleştirilmiş bir yaklaşımdır.
                self.emit_line("  syscall"); // Sistem çağrısını tetikle
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 arasında seçim yapın.
                // Sahne64'ün kendi 'print' fonksiyonları varsa onları çağır.
                // Örneğin:
                match ty {
                    Type::Integer => {
                        self.emit_line("  pushq %rdi"); // Argümanı stack'e it
                        self.emit_line("  call sahne_print_int"); // Sahne64 runtime fonksiyonu
                        self.emit_line("  addq $8, %rsp"); // Argümanı stack'ten temizle
                    }
                    Type::Boolean => {
                         self.emit_line("  pushq %rdi");
                         self.emit_line("  call sahne_print_bool");
                         self.emit_line("  addq $8, %rsp");
                    }
                    Type::String => {
                        self.emit_line("  pushq %rdi");
                        self.emit_line("  call sahne_print_string");
                        self.emit_line("  addq $8, %rsp");
                    }
                    _ => {
                        // Fallback to Karnal64 syscall if Sahne64 API not available or unknown type
                        // (Yukarıdaki KernelOnly kısmı gibi)
                        self.emit_line("  movq $1, %rax");
                        self.emit_line("  movq $1, %rdi");
                        self.emit_line("  movq %rdi, %rsi");
                        self.emit_line("  movq $8, %rdx");
                        self.emit_line("  syscall");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line("  movq $1, %rax");
                self.emit_line("  movq $1, %rdi");
                self.emit_line("  movq %rdi, %rsi");
                self.emit_line("  movq $8, %rdx");
                self.emit_line("  syscall");
            }
        }
        Ok(())
    }

    /// Çıktı assembly'ye bir satır ekler.
    fn emit_line(&mut self, line: &str) {
        self.output_assembly.push_str(line);
        self.output_assembly.push_str("\n");
    }
}
