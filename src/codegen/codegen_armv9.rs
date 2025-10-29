// codegen_aarch64.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// AArch64 mimarisi için kod üreticisi
pub struct AArch64CodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    /// IRGenerator'daki patch mekanizması burada da uygulanacak.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl AArch64CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        AArch64CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den AArch64 assembly kodu üretir.
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
            self.generate_aarch64_function(func)?;
        }

        self.emit_postlude();

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (.data, .text bölümleri vb.)
    fn emit_prelude(&mut self) {
        self.emit_line(".section .data");
        self.emit_line(".align 3"); // 8-bayt hizalama (veri için)
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        // Genellikle AArch64'te özel bir postlude gerekmeyebilir.
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
                        // AArch64'te stringler için .asciz (ASCII string, null-terminated)
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
            self.emit_line(".align 3"); // 8-bayt hizalama
        }

        self.emit_line(".section .text");
        self.emit_line(".align 2"); // Fonksiyonlar için 4-bayt hizalama
        Ok(())
    }

    /// Tek bir fonksiyonun AArch64 assembly kodunu üretir.
    fn generate_aarch64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".global {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".type {}, %function", func_name)); // Fonksiyon tipini belirt
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // x29 (FP) ve x30 (LR) kaydedicilerini stack'e kaydet
        // Stack 16 bayt hizalı olmalı
        self.emit_line("  stp x29, x30, [sp, #-16]!"); // x29, x30'ı stack'e kaydet ve sp'yi 16 azalt
        self.emit_line("  mov x29, sp");              // x29'ı (FP) mevcut sp'ye ayarla

        // Yerel değişkenler için yığın alanı ayır
        // Her değişken için 8 bayt yer varsayalım (64-bit)
        // Yerel değişken alanı 16 baytın katı olmalı.
        let mut local_vars_size = func.next_local_offset * 8;
        if local_vars_size % 16 != 0 {
            local_vars_size = (local_vars_size / 16 + 1) * 16; // 16'nın katına yuvarla
        }
        if local_vars_size > 0 {
            self.emit_line(&format!("  sub sp, sp, #{}", local_vars_size));
        }

        // Parametreleri yerel değişken ofsetlerine kopyala
        // AArch64 çağrı kuralı: X0-X7 argümanlar için kullanılır.
        for i in 0..func.parameter_count {
            let arg_reg = match i {
                0 => "x0", 1 => "x1", 2 => "x2", 3 => "x3",
                4 => "x4", 5 => "x5", 6 => "x6", 7 => "x7",
                _ => { /* Stack üzerinden argümanlar: Daha karmaşık işlem, şimdilik sadece 8 argüman */ continue; }
            };
            // Yerel değişken ofseti: FP'ye göre negatif ofset
            // (parametreler, yerel değişken alanı içindeki en düşük adreslerden başlar)
            let offset_from_fp = (i * 8) as isize - local_vars_size as isize;
            self.emit_line(&format!("  str {}, [x29, #{}]", arg_reg, offset_from_fp));
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            // Her yönerge için bir etiket tanımla (Jump hedefleri için)
            // IRGenerator'daki etiket düzeltme mekanizmasının burada da uygulanması gerekiyor.
            // IRInstruction'ların indeksleri etiket olarak kullanılabilir.
            self.emit_line(&format!(".L_{}_{}:", func_name, i));

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  mov x0, #{}", val)); // Integer'ı x0'a yükle
                    self.emit_line("  str x0, [sp, #-8]!");     // x0'ı stack'e it
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  mov x0, #{}", bool_val));
                    self.emit_line("  str x0, [sp, #-8]!");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        self.emit_line(&format!("  adrp x0, {}", label)); // String etiketinin sayfa adresini x0'a yükle
                        self.emit_line(&format!("  add x0, x0, :lo12:{}", label)); // Ofseti ekle
                        self.emit_line("  str x0, [sp, #-8]!");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    let offset_from_fp = (offset * 8) as isize - local_vars_size as isize;
                    self.emit_line(&format!("  ldr x0, [x29, #{}]", offset_from_fp)); // Yerel değişkeni x0'a yükle
                    self.emit_line("  str x0, [sp, #-8]!"); // x0'ı stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  ldr x0, [sp], #8"); // Stack'ten değeri x0'a al ve sp'yi artır
                    let offset_from_fp = (offset * 8) as isize - local_vars_size as isize;
                    self.emit_line(&format!("  str x0, [x29, #{}]", offset_from_fp)); // x0'ı yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  adrp x0, {}", label)); // Global değişken adresini x0'a yükle
                        self.emit_line(&format!("  add x0, x0, :lo12:{}", label));
                        self.emit_line("  ldr x0, [x0]"); // Adresteki değeri x0'a yükle
                        self.emit_line("  str x0, [sp, #-8]!");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  ldr x0, [sp], #8"); // Yığından değeri x0'a al ve pop et
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  adrp x1, {}", label)); // Global değişken adresini x1'e yükle
                        self.emit_line(&format!("  add x1, x1, :lo12:{}", label));
                        self.emit_line("  str x0, [x1]"); // x0'ı adrese kaydet
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_aarch64_binary_op("add"),
                OpCode::Sub => self.emit_aarch64_binary_op("sub"),
                OpCode::Mul => self.emit_aarch64_binary_op("mul"),
                OpCode::Div => self.emit_aarch64_binary_op("sdiv"), // Signed Division
                OpCode::Eq => self.emit_aarch64_comparison_op("cmp", "cset eq"),
                OpCode::Ne => self.emit_aarch64_comparison_op("cmp", "cset ne"),
                OpCode::Lt => self.emit_aarch64_comparison_op("cmp", "cset lt"),
                OpCode::Le => self.emit_aarch64_comparison_op("cmp", "cset le"),
                OpCode::Gt => self.emit_aarch64_comparison_op("cmp", "cset gt"),
                OpCode::Ge => self.emit_aarch64_comparison_op("cmp", "cset ge"),
                OpCode::And => self.emit_aarch64_binary_op("and"),
                OpCode::Or => self.emit_aarch64_binary_op("orr"),
                OpCode::Not => {
                    self.emit_line("  ldr x0, [sp]");     // Yığından değeri x0'a al
                    self.emit_line("  cmp x0, #0");       // x0'ı 0 ile karşılaştır
                    self.emit_line("  cset eq x0");      // Eşitse x0=1, değilse x0=0 (boolean NOT)
                    self.emit_line("  str x0, [sp]");     // Sonucu yığına kaydet
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  b .L_{}_{}", func_name, target_idx));
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  ldr x0, [sp], #8"); // Yığından değeri al ve pop et
                    self.emit_line("  cmp x0, #0");       // x0'ı 0 ile karşılaştır
                    self.emit_line(&format!("  beq .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından X0-X7 registerlarına yükle (sağdan sola)
                    for i in 0..*arg_count {
                        let arg_reg = match i {
                            0 => "x0", 1 => "x1", 2 => "x2", 3 => "x3",
                            4 => "x4", 5 => "x5", 6 => "x6", 7 => "x7",
                            _ => { /* Fazla argümanlar için stack'ten doğrudan kullanım */ continue; }
                        };
                        // Argümanlar yığında ters sırada olduğu için (Push sırası)
                        // (arg_count - 1 - i). argümanı al.
                        let stack_offset = (*arg_count - 1 - i) * 8;
                        self.emit_line(&format!("  ldr {}, [sp, #{}]", arg_reg, stack_offset));
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  add sp, sp, #{}", arg_count * 8));

                    self.emit_line(&format!("  bl {}", callee_name)); // Fonksiyonu çağır (Branch with Link)

                    // Dönüş değeri X0'da olur (eğer varsa), onu yığına it
                    self.emit_line("  str x0, [sp, #-8]!");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa X0'a yükle
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  ldr x0, [sp], #8"); // Yığından değeri x0'a al ve pop et
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    if local_vars_size > 0 {
                        self.emit_line(&format!("  add sp, sp, #{}", local_vars_size)); // Yerel değişken alanını geri al
                    }
                    self.emit_line("  ldp x29, x30, [sp], #16"); // x29, x30'ı stack'ten geri yükle ve sp'yi 16 artır
                    self.emit_line("  ret"); // Fonksiyondan dön (x30'daki adrese atla)
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_aarch64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_aarch64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_aarch64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// AArch64 için ikili operatör kodu üretir.
    fn emit_aarch64_binary_op(&mut self, instruction: &str) {
        self.emit_line("  ldr x1, [sp], #8"); // Sağ operandı x1'e yükle ve pop et
        self.emit_line("  ldr x0, [sp]");     // Sol operandı x0'a yükle (pop etme)
        self.emit_line(&format!("  {} x0, x0, x1", instruction)); // İşlemi yap (x0 = x0 op x1)
        self.emit_line("  str x0, [sp]");     // Sonucu yığına kaydet
    }

    /// AArch64 için karşılaştırma operatörü kodu üretir.
    fn emit_aarch64_comparison_op(&mut self, cmp_instr: &str, cset_instr: &str) {
        self.emit_line("  ldr x1, [sp], #8"); // Sağ operandı x1'e yükle ve pop et
        self.emit_line("  ldr x0, [sp]");     // Sol operandı x0'a yükle
        self.emit_line(&format!("  {} x0, x1", cmp_instr)); // x0 ile x1'i karşılaştır
        self.emit_line(&format!("  {} x0", cset_instr)); // Durum bayraklarına göre x0'ı 0 veya 1 yap
        self.emit_line("  str x0, [sp]");     // Sonucu yığına kaydet
    }

    /// AArch64 için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_aarch64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  ldr x0, [sp], #8"); // Yığından değeri x0'a yükle (argüman 1)

        let syscall_num = match ty {
            Type::Integer => 64, // `write` syscall numarası (Linux AArch64 ABI'ye göre)
            Type::Boolean => 64, // Boolean'ı da int gibi yazdırabiliriz
            Type::String => 64,  // String için de `write`
            _ => {
                return Err(CompilerError::CodeGen(CodeGenError::UnsupportedTypeForSyscall {
                    ty: ty.to_string(),
                    syscall_name: "print".to_string(),
                    line: 0, // Bu bilgiyi IRInstruction'dan almak daha iyi olur
                    column: 0,
                }));
            }
        };

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                // write syscall: X0=fd (1 for stdout), X1=buf, X2=count
                // Sayı ve boolean için: Sayıyı bir string'e çevirmek ve sonra yazmak gerekir.
                // Basitlik için sadece X0'daki değeri yazdırdığını varsayalım.
                // Gerçekte, bir runtime desteği veya daha karmaşık bir çeviri gerekir.
                self.emit_line("  mov x8, #64"); // Syscall numarası (write)
                self.emit_line("  mov x1, x0"); // x0'daki değeri x1'e taşı (buf)
                self.emit_line("  mov x0, #1"); // stdout (fd=1)
                self.emit_line("  mov x2, #8"); // String için 8 bayt (long size, varsayımsal)
                                               // Integer/Boolean için: sayıyı string'e çevirmesi gerekir
                                               // Bu kısım daha karmaşık ve runtime desteği ister.
                self.emit_line("  svc #0"); // Sistem çağrısını tetikle
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 arasında seçim yapın.
                // Sahne64'ün kendi 'print' fonksiyonları varsa onları çağır.
                // Örneğin:
                match ty {
                    Type::Integer => {
                        self.emit_line("  bl sahne_print_int"); // Sahne64 runtime fonksiyonu
                    }
                    Type::Boolean => {
                         self.emit_line("  bl sahne_print_bool"); // Sahne64 runtime fonksiyonu
                    }
                    Type::String => {
                        self.emit_line("  bl sahne_print_string"); // Sahne64 runtime fonksiyonu
                    }
                    _ => {
                        // Fallback to Karnal64 syscall if Sahne64 API not available or unknown type
                        // (Yukarıdaki KernelOnly kısmı gibi)
                        self.emit_line("  mov x8, #64"); // Syscall numarası (write)
                        self.emit_line("  mov x1, x0"); // x0'daki değeri x1'e taşı (buf)
                        self.emit_line("  mov x0, #1"); // stdout (fd=1)
                        self.emit_line("  mov x2, #8"); // Varsayımsal boyut
                        self.emit_line("  svc #0");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line("  mov x8, #64");
                self.emit_line("  mov x1, x0");
                self.emit_line("  mov x0, #1");
                self.emit_line("  mov x2, #8");
                self.emit_line("  svc #0");
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
