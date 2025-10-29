// codegen_sparc64.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// SPARC64 mimarisi için kod üreticisi
pub struct Sparc64CodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl Sparc64CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        Sparc64CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den SPARC64 assembly kodu üretir.
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
            self.generate_sparc64_function(func)?;
        }

        self.emit_postlude();

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (.data, .text bölümleri vb.)
    fn emit_prelude(&mut self) {
        self.emit_line(".section \".data\""); // Veri bölümü
        self.emit_line(".align 8");          // 8-bayt hizalama (veri için)
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        // Genellikle SPARC64'te özel bir postlude gerekmeyebilir.
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
                        // SPARC64'te stringler için .asciz (ASCII string, null-terminated)
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
            self.emit_line("  .xword 0"); // 64-bit sıfır değeriyle başlat (8 bayt)
            self.emit_line(".align 8"); // 8-bayt hizalama
        }

        self.emit_line(".section \".text\""); // Kod bölümü
        self.emit_line(".align 8");           // Fonksiyonlar için 8-bayt hizalama (genellikle 4 veya 8)
        Ok(())
    }

    /// Tek bir fonksiyonun SPARC64 assembly kodunu üretir.
    fn generate_sparc64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".global {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".type {}, #function", func_name)); // Fonksiyon tipini belirt
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // SPARC ABI'si, çağıranın stack'te 160 baytlık (SA_MIN_WINDOW) bir "çıkarma alanı" (save area) bırakmasını gerektirir.
        // Bu alan, kaydedici pencereleri kaydedildiğinde kullanılır.
        // %sp'den gerekli yerel değişkenler ve kaydedici kaydetme alanı için yer ayır.
        // En az 160 baytlık bir çerçeve garanti etmeliyiz.
        let mut frame_size = func.next_local_offset * 8; // Yerel değişkenler için 8 bayt
        // Stack frame boyutu 16 bayt hizalı olmalı ve min. pencere alanı için yer açmalı.
        frame_size = ((frame_size + 159) / 16) * 16; // 160 bayt minimum alan ve 16 bayt hizalama

        // Save yönergesi: Kaydedici penceresini kaydırır, %sp'yi azaltır ve %fp'yi ayarlar.
        // save %sp, -frame_size, %sp
        // %sp, -frame_size: Yeni stack pointer'ı.
        // %sp: Mevcut stack pointer'ı (%o6)
        // %fp: Yeni frame pointer (%i6), %sp'ye göre ayarlanır.
        self.emit_line(&format!("  save %sp, -{}, %sp", frame_size));

        // Parametreleri yerel değişken ofsetlerine kopyala
        // SPARC ABI: %i0-%i5 (gelen argümanlar) kullanılır.
        // Bu argümanlar, save yönergesinden sonra otomatik olarak %i kaydedicilerine eşlenir.
        // Ancak biz bunları yine de stack'e taşıyabiliriz.
        let arg_regs = ["%i0", "%i1", "%i2", "%i3", "%i4", "%i5"]; // İlk 6 argüman
        for i in 0..func.parameter_count {
            if i < arg_regs.len() {
                let arg_reg = arg_regs[i];
                // Yerel değişken ofseti: %fp'ye göre negatif ofset
                // %fp, save yönergesinden sonra eski %sp + 160 (min_window_size) olarak ayarlanır.
                // Yerel değişkenler %fp'nin altında tutulur.
                let offset_from_fp = (i * 8) as isize; // Basitçe parametre ofseti
                self.emit_line(&format!("  stx {}, [ %fp + {} ]", arg_reg, offset_from_fp));
            } else {
                // Kalan argümanlar stack'ten alınır.
                // %fp'ye göre ofset: (param_idx - 6) * 8 + SA_MIN_WINDOW + 8 (dönüş adresi)
                // Bu oldukça karmaşık. Şimdilik sadece ilk 6 argümanı destekleyelim.
                eprintln!("Uyarı: SPARC64'te 6'dan fazla argüman şu an desteklenmiyor.");
            }
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            self.emit_line(&format!(".L_{}_{}:", func_name, i)); // Etiketler

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  mov {}, %g1", val)); // Integer'ı %g1'e yükle
                    self.emit_line("  stx %g1, [ %sp + -8 ]!"); // %g1'i stack'e it
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  mov {}, %g1", bool_val));
                    self.emit_line("  stx %g1, [ %sp + -8 ]!");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        // Global veri adresleri için %hi/%lo kullanırız
                        self.emit_line(&format!("  sethi %hi({}), %g1", label)); // Üst 22 bit
                        self.emit_line(&format!("  or %g1, %lo({}), %g1", label)); // Alt 10 bit
                        self.emit_line("  stx %g1, [ %sp + -8 ]!"); // %g1'i stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    // Yerel değişkenler %fp'nin altında yer alır.
                    let offset_from_fp = (offset * 8) as isize; // ofset parametre sayısından sonraki yerel değişken sırası
                    self.emit_line(&format!("  ldx [ %fp + {} ], %g1", offset_from_fp)); // Yerel değişkeni %g1'e yükle
                    self.emit_line("  stx %g1, [ %sp + -8 ]!"); // %g1'i stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  ldx [ %sp + 0 ], %g1"); // Stack'ten değeri %g1'e al
                    self.emit_line("  add %sp, 8, %sp");      // Stack'ten pop et
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  stx %g1, [ %fp + {} ]", offset_from_fp)); // %g1'i yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  sethi %hi({}), %g1", label));
                        self.emit_line(&format!("  or %g1, %lo({}), %g1", label));
                        self.emit_line("  ldx [ %g1 + 0 ], %g1"); // Global değişkenin değerini %g1'e yükle
                        self.emit_line("  stx %g1, [ %sp + -8 ]!");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  ldx [ %sp + 0 ], %g1"); // Stack'ten değeri %g1'e al
                    self.emit_line("  add %sp, 8, %sp");      // Stack'ten pop et
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  sethi %hi({}), %g2", label));
                        self.emit_line(&format!("  or %g2, %lo({}), %g2", label));
                        self.emit_line("  stx %g1, [ %g2 + 0 ]"); // %g1'i global değişkene kaydet
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_sparc64_binary_op("add"),
                OpCode::Sub => self.emit_sparc64_binary_op("sub"),
                OpCode::Mul => self.emit_sparc64_binary_op("mulx"), // 64-bit çarpma
                OpCode::Div => self.emit_sparc64_binary_op("sdivx"), // 64-bit işaretli bölme
                OpCode::Eq => self.emit_sparc64_comparison_op("xcc", "be", "bne"), // xcc: integer condition codes
                OpCode::Ne => self.emit_sparc64_comparison_op("xcc", "bne", "be"),
                OpCode::Lt => self.emit_sparc64_comparison_op("xcc", "bl", "bg"),
                OpCode::Le => self.emit_sparc64_comparison_op("xcc", "ble", "bge"),
                OpCode::Gt => self.emit_sparc64_comparison_op("xcc", "bg", "bl"),
                OpCode::Ge => self.emit_sparc64_comparison_op("xcc", "bge", "ble"),
                OpCode::And => self.emit_sparc64_binary_op("and"),
                OpCode::Or => self.emit_sparc64_binary_op("or"),
                OpCode::Not => {
                    self.emit_line("  ldx [ %sp + 0 ], %g1"); // Değeri %g1'e al
                    self.emit_line("  cmp %g1, 0");           // %g1'i 0 ile karşılaştır
                    self.emit_line("  movr %xcc, 1, %g1");    // 0 ise %g1=1 (TRUE), değilse %g1=0 (FALSE) (move if register condition)
                    self.emit_line("  stx %g1, [ %sp + 0 ]"); // Sonucu stack'e kaydet
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  b .L_{}_{}", func_name, target_idx));
                    self.emit_line("  nop"); // Gecikme slotu (branch delay slot)
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  ldx [ %sp + 0 ], %g1"); // Koşulu %g1'e al
                    self.emit_line("  add %sp, 8, %sp");      // Pop et
                    self.emit_line("  cmp %g1, 0");           // %g1'i 0 ile karşılaştır
                    self.emit_line(&format!("  be .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                    self.emit_line("  nop"); // Gecikme slotu
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından %o0-%o5 kaydedicilerine yükle (sağdan sola)
                    // SPARC ABI: %o0-%o5 ilk 6 argüman için kullanılır.
                    let arg_output_regs = ["%o0", "%o1", "%o2", "%o3", "%o4", "%o5"];
                    for i in 0..*arg_count {
                        if i < arg_output_regs.len() {
                            let arg_reg = arg_output_regs[i];
                            // Argümanlar yığında ters sırada olduğu için
                            let stack_offset = (*arg_count - 1 - i) * 8;
                            self.emit_line(&format!("  ldx [ %sp + {} ], {}", stack_offset, arg_reg));
                        } else {
                            // Kalan argümanlar stack'ten doğrudan geçirilir.
                            // Bu kısım çok daha karmaşık ve genellikle bir runtime fonksiyonuna sarılır.
                            eprintln!("Uyarı: SPARC64'te 6'dan fazla argüman şu an desteklenmiyor.");
                        }
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  add %sp, {}, %sp", arg_count * 8));

                    self.emit_line(&format!("  call {}", callee_name)); // Fonksiyonu çağır
                    self.emit_line("  nop"); // Gecikme slotu (genellikle 1 nop)

                    // Dönüş değeri %o0'da olur, onu yığına it
                    self.emit_line("  stx %o0, [ %sp + -8 ]!");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa %o0'a yükle (yığının tepesinden)
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  ldx [ %sp + 0 ], %o0");
                    //     self.emit_line("  add %sp, 8, %sp"); // Pop et
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    self.emit_line("  restore %g0, %g0, %g0"); // Kaydedici penceresini geri kaydır (restore instruction)
                    self.emit_line("  jmp %i7+8");             // Dönüş adresi %i7'de, +8 sonraki yönergeye atlar
                    self.emit_line("  nop");                   // Gecikme slotu
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_sparc64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_sparc64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_sparc64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// SPARC64 için ikili operatör kodu üretir.
    fn emit_sparc64_binary_op(&mut self, instruction: &str) {
        self.emit_line("  ldx [ %sp + 0 ], %g2"); // Sağ operandı %g2'ye yükle
        self.emit_line("  add %sp, 8, %sp");      // Pop et
        self.emit_line("  ldx [ %sp + 0 ], %g1"); // Sol operandı %g1'e yükle
        self.emit_line(&format!("  {} %g1, %g2, %g1", instruction)); // İşlemi yap (%g1 = %g1 op %g2)
        self.emit_line("  stx %g1, [ %sp + 0 ]"); // Sonucu stack'e kaydet
    }

    /// SPARC64 için karşılaştırma operatörü kodu üretir.
    /// `cond_reg` : hangi condition register'ı (örn: xcc, fcc0)
    /// `true_branch_instr`: koşul doğruysa atlama yönergesi (örn: be)
    /// `false_branch_instr`: koşul yanlışsa atlama yönergesi (örn: bne)
    fn emit_sparc64_comparison_op(&mut self, cond_reg: &str, true_branch_instr: &str, false_branch_instr: &str) {
        self.emit_line("  ldx [ %sp + 0 ], %g2"); // Sağ operandı %g2'ye
        self.emit_line("  add %sp, 8, %sp");      // Pop et
        self.emit_line("  ldx [ %sp + 0 ], %g1"); // Sol operandı %g1'e

        self.emit_line(&format!("  cmp %g1, %g2")); // %g1 ile %g2'yi karşılaştır

        let true_label = String::from_format_args!(".L_true_{}", self.next_string_id);
        let end_label = String::from_format_args!(".L_end_{}", self.next_string_id);
        self.next_string_id += 1;

        // branch_if_true, nop
        self.emit_line(&format!("  {} %{}, {}", true_branch_instr, cond_reg, true_label));
        self.emit_line("  nop"); // Gecikme slotu

        // else (false)
        self.emit_line("  mov 0, %g1"); // %g1 = 0 (False)
        self.emit_line("  b ");
        self.emit_line(&format!("  jmp {}", end_label)); // Atla
        self.emit_line("  nop"); // Gecikme slotu

        // true
        self.emit_line(&format!("{}:", true_label));
        self.emit_line("  mov 1, %g1"); // %g1 = 1 (True)

        self.emit_line(&format!("{}:", end_label));
        self.emit_line("  stx %g1, [ %sp + 0 ]"); // Sonucu stack'e kaydet
    }


    /// SPARC64 için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_sparc64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  ldx [ %sp + 0 ], %o0"); // Yığından değeri %o0'a yükle (argüman 1: buffer/value)
        self.emit_line("  add %sp, 8, %sp");      // Pop et

        // write syscall: %g1=2, %o0=fd (1 for stdout), %o1=buf, %o2=count
        // SPARC64 Linux ABI'de write syscall numarası 2'dir.
        let syscall_num = 2;

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                self.emit_line(&format!("  mov {}, %g1", syscall_num)); // Syscall numarası %g1'e
                self.emit_line("  mov 1, %o0");                       // stdout (fd=1)
                self.emit_line("  mov %o0, %o1");                     // %o0'daki değeri %o1'e taşı (buf - değerin kendisi)
                self.emit_line("  mov 8, %o2");                       // 8 bayt yazdır (long size, varsayımsal)
                                                                      // NOTE: Integer/Boolean için, sayıyı string'e çevirmesi gerekir
                                                                      // Bu basitleştirilmiş bir yaklaşımdır.
                self.emit_line("  tcc 0"); // Sistem çağrısını tetikle (trap on condition code 0)
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 arasında seçim yapın.
                match ty {
                    Type::Integer => {
                        self.emit_line("  call sahne_print_int"); // Sahne64 runtime fonksiyonu
                        self.emit_line("  nop"); // Gecikme slotu
                    }
                    Type::Boolean => {
                         self.emit_line("  call sahne_print_bool");
                         self.emit_line("  nop");
                    }
                    Type::String => {
                        self.emit_line("  call sahne_print_string");
                        self.emit_line("  nop");
                    }
                    _ => {
                        // Fallback to Karnal64 syscall
                        self.emit_line(&format!("  mov {}, %g1", syscall_num));
                        self.emit_line("  mov 1, %o0");
                        self.emit_line("  mov %o0, %o1");
                        self.emit_line("  mov 8, %o2");
                        self.emit_line("  tcc 0");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line(&format!("  mov {}, %g1", syscall_num));
                self.emit_line("  mov 1, %o0");
                self.emit_line("  mov %o0, %o1");
                self.emit_line("  mov 8, %o2");
                self.emit_line("  tcc 0");
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
