// codegen.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, TargetArch, OptimizationMode};
use crate::type_system::Type; // IR'den gelen tür bilgisini kullanmak için
use crate::error::{CompilerError, Result, CodeGenError}; // Hata yönetimi için
use sahne64::utils::{Vec, String, HashMap}; // No_std uyumlu koleksiyonlar
use sahne64::{print, println, eprintln}; // Konsol çıktıları için

/// Kod üreticisi
pub struct CodeGenerator {
    target_config: TargetConfig,
    /// Üretilen assembly kodunu tutar
    output_assembly: String,
    /// Global değişkenler için bellek konumlarını tutar (şimdilik basit bir sembol tablosu gibi)
    global_variable_addresses: HashMap<String, usize>, // Adı -> Bellek adresi/ofseti
    /// String sabitleri için bellek konumlarını tutar
    string_literals: HashMap<String, String>, // String içeriği -> Etiket adı
    next_string_id: usize, // Yeni string etiketleri için sayaç
}

impl CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
        }
    }

    /// IRModule'den hedef mimari için assembly kodu üretir.
    pub fn generate_assembly(&mut self, ir_module: &IRModule) -> Result<String> {
        self.output_assembly.clear();
        self.string_literals.clear();
        self.next_string_id = 0;

        self.emit_prelude(); // Başlangıç ayarları (örn. .data, .text bölümleri)

        // 1. Global değişkenleri ve string sabitlerini işle
        self.emit_data_section(ir_module)?;

        // 2. Fonksiyonları işle
        for func in ir_module.functions.values() {
            self.generate_function_assembly(func)?;
        }

        self.emit_postlude(); // Bitiş ayarları

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (örn. .data, .text bölümleri)
    fn emit_prelude(&mut self) {
        match self.target_config.arch {
            TargetArch::Riscv64 => {
                self.emit_line(".section .data");
                self.emit_line(".align 3"); // 8-bayt hizalama (64-bit için)
            }
            _ => { /* Diğer mimariler için başlangıç */ }
        }
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        match self.target_config.arch {
            TargetArch::Riscv64 => {
                // Herhangi bir sonlandırma kodu veya boşluk ekleme
            }
            _ => { /* Diğer mimariler için bitiş */ }
        }
    }

    /// Veri bölümünü (global değişkenler, string sabitleri) üretir.
    fn emit_data_section(&mut self, ir_module: &IRModule) -> Result<()> {
        match self.target_config.arch {
            TargetArch::Riscv64 => {
                // String sabitlerini topla ve etiketlerini oluştur
                for func in ir_module.functions.values() {
                    for inst in func.instructions.iter() {
                        if let OpCode::PushString(s) = &inst.opcode {
                            // Eğer string daha önce eklenmediyse, yeni bir etiket ve veri tanımla
                            if !self.string_literals.contains_key(s) {
                                let label = String::from_format_args!("__str_{}", self.next_string_id);
                                self.next_string_id += 1;
                                self.string_literals.insert(s.clone(), label.clone());
                                self.emit_line(&format!("{}: .string \"{}\"", label, s));
                            }
                        }
                    }
                }
                // Global değişkenler için yer ayır
                for (name, _offset) in ir_module.global_variables.iter() {
                    // Şimdilik her global değişken için 8 baytlık bir alan ayıralım (64-bit)
                    self.emit_line(&format!("{}: .word 0", name)); // .word (4 bayt) yerine .dword (8 bayt) kullanılabilir
                                                                        // Ancak RISC-V GNU AS'de .dword yok, .8byte kullanılabilir.
                    self.emit_line(&format!(".align 3")); // Hizalama
                    self.emit_line(&format!("{}: .zero 8", name)); // 8 bayt sıfırla
                    // Alternatif: {}: .byte 0,0,0,0,0,0,0,0
                    // VEYA: {}: .quad 0
                }

                self.emit_line(".section .text");
                self.emit_line(".align 2"); // Fonksiyonlar için hizalama
            }
            _ => {
                return Err(CompilerError::CodeGen(CodeGenError::UnsupportedArchitecture {
                    arch: format!("{:?}", self.target_config.arch),
                    message: "Data bölümü üretimi desteklenmiyor".to_string(),
                }));
            }
        }
        Ok(())
    }

    /// Tek bir fonksiyonun assembly kodunu üretir.
    fn generate_function_assembly(&mut self, func: &IRFunction) -> Result<()> {
        match self.target_config.arch {
            TargetArch::Riscv64 => self.generate_riscv64_function(func),
             TargetArch::Aarch64 => self.generate_aarch64_function(func),
             TargetArch::X86_64 => self.generate_x86_64_function(func),
            _ => {
                Err(CompilerError::CodeGen(CodeGenError::UnsupportedArchitecture {
                    arch: format!("{:?}", self.target_config.arch),
                    message: "Fonksiyon kodu üretimi desteklenmiyor".to_string(),
                }))
            }
        }
    }

    /// RISC-V 64 mimarisi için fonksiyon assembly kodunu üretir.
    fn generate_riscv64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".globl {}", func_name));
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Basit)
        // `ra` (dönüş adresi) ve `fp` (frame pointer) kaydet
        // Stack pointer'ı ayarla (yerel değişkenler için yer aç)
        // s0 (fp) kaydedeceğiz.
        self.emit_line("  addi sp, sp, -16"); // stack pointer'ı 16 bayt azalt
        self.emit_line("  sd ra, 8(sp)");    // ra'yı stack'e kaydet (sp+8)
        self.emit_line("  sd s0, 0(sp)");    // s0'ı (eski fp) stack'e kaydet (sp+0)
        self.emit_line("  addi s0, sp, 16"); // s0'ı (yeni fp) mevcut sp'den 16 bayt yukarıya ayarla (stack frame'in tepesi)

        // Yerel değişkenler için yığın alanı ayır
        // Her değişken için 8 baytlık yer varsayalım (64-bit)
        let local_vars_size = func.next_local_offset * 8; // Toplam yerel değişken alanı
        // Parametreler zaten stack'e itildiği için, buradaki ofsetleri düzgün yönetmeliyiz.
        // Basitlik için tüm yerel değişkenler için yer açalım, parametreler de buna dahil olsun.
        self.emit_line(&format!("  addi sp, sp, -{}", local_vars_size));

        // Parametreleri yerel değişken ofsetlerine kopyala
        // RISC-V çağrı kuralı: a0-a7 argümanlar için.
        // İlk N argüman a0, a1, ..., aN-1 içinde gelir.
        for i in 0..func.parameter_count {
            // Argüman kaydı (a0, a1, ...)
            let arg_reg = match i {
                0 => "a0", 1 => "a1", 2 => "a2", 3 => "a3",
                4 => "a4", 5 => "a5", 6 => "a6", 7 => "a7",
                _ => { /* Stack üzerinden argümanlar için daha karmaşık işleme */ continue; }
            };
            // Yerel değişken ofseti (parametreler 0'dan başlar)
            // FP'ye göre ofset: (param_offset * 8) - local_vars_size
            // Yani, (0. parametre) fp-local_vars_size + (0*8)
            // (1. parametre) fp-local_vars_size + (1*8)
            let local_offset_from_fp = (i as isize * 8) - local_vars_size as isize;
            self.emit_line(&format!("  sd {}, {}(s0)", arg_reg, local_offset_from_fp));
        }

        // Yönergeleri Çevir
        for inst in func.instructions.iter() {
            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  li t0, {}", val)); // Integer'ı t0'a yükle
                    self.emit_line("  addi sp, sp, -8"); // Stack'te 8 bayt yer aç
                    self.emit_line("  sd t0, 0(sp)");   // t0'ı stack'e kaydet
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  li t0, {}", bool_val));
                    self.emit_line("  addi sp, sp, -8");
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        self.emit_line(&format!("  la t0, {}", label)); // String etiketinin adresini t0'a yükle
                        self.emit_line("  addi sp, sp, -8");
                        self.emit_line("  sd t0, 0(sp)");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    // Yerel değişken ofsetini FP'ye göre ayarla
                    // offset parametre ve yerel değişkenlerin toplam sayısıdır.
                    // Stack'te yerel değişkenler FP'nin altında tutulur.
                    // Yerel değişkenler için ofset FP'ye göre negatif olur.
                    // Örn: -8(s0), -16(s0)
                    let stack_offset = (offset * 8) as isize; // ofset, parametre sayısından sonraki yerel değişken sırası
                    let local_offset_from_fp = stack_offset - local_vars_size as isize; // local_vars_size parametreleri de içerdiği için
                                                                                            // FP'ye göre tüm yerel değişkenlerin başlangıcıdır.
                    self.emit_line(&format!("  ld t0, {}(s0)", local_offset_from_fp)); // Değişkeni stack'ten t0'a yükle
                    self.emit_line("  addi sp, sp, -8");
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  ld t0, 0(sp)");   // Yığından değeri t0'a al
                    self.emit_line("  addi sp, sp, 8"); // Yığından değeri pop et
                    let stack_offset = (offset * 8) as isize;
                    let local_offset_from_fp = stack_offset - local_vars_size as isize;
                    self.emit_line(&format!("  sd t0, {}(s0)", local_offset_from_fp)); // t0'ı yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    self.emit_line(&format!("  la t0, {}", name)); // Global değişkenin adresini t0'a yükle
                    self.emit_line("  ld t0, 0(t0)"); // Adresteki değeri t0'a yükle
                    self.emit_line("  addi sp, sp, -8");
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  ld t0, 0(sp)");   // Yığından değeri t0'a al
                    self.emit_line("  addi sp, sp, 8"); // Yığından değeri pop et
                    self.emit_line(&format!("  la t1, {}", name)); // Global değişkenin adresini t1'e yükle
                    self.emit_line("  sd t0, 0(t1)"); // t0'ı adrese kaydet
                }
                OpCode::Add => self.emit_binary_op("add"),
                OpCode::Sub => self.emit_binary_op("sub"),
                OpCode::Mul => self.emit_binary_op("mul"),
                OpCode::Div => self.emit_binary_op("div"),
                OpCode::Eq => self.emit_comparison_op("seqz"), // a == b -> (a-b) == 0
                OpCode::Ne => self.emit_comparison_op("snez"), // a != b -> (a-b) != 0
                OpCode::Lt => self.emit_comparison_op("slt"),  // a < b
                OpCode::Le => { // a <= b  <=> !(a > b)
                    self.emit_binary_op("sgt"); // t0 = (a > b) ? 1 : 0
                    self.emit_line("  not t0, t0"); // t0 = !t0
                    self.emit_line("  addi sp, sp, -8"); // Sonucu yığına push
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::Gt => self.emit_comparison_op("sgt"), // a > b
                OpCode::Ge => { // a >= b <=> !(a < b)
                    self.emit_binary_op("slt"); // t0 = (a < b) ? 1 : 0
                    self.emit_line("  not t0, t0"); // t0 = !t0
                    self.emit_line("  addi sp, sp, -8"); // Sonucu yığına push
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::And => { // a && b
                    self.emit_line("  ld t1, 0(sp)");   // b
                    self.emit_line("  addi sp, sp, 8");
                    self.emit_line("  ld t0, 0(sp)");   // a
                    // Basitlik için: a ve b non-zero ise true.
                    self.emit_line("  and t0, t0, t1");
                    // Eğer sonuç sıfırsa false, değilse true (boolean 1 veya 0)
                    self.emit_line("  snez t0, t0"); // t0 = (t0 != 0) ? 1 : 0
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::Or => { // a || b
                    self.emit_line("  ld t1, 0(sp)");   // b
                    self.emit_line("  addi sp, sp, 8");
                    self.emit_line("  ld t0, 0(sp)");   // a
                    self.emit_line("  or t0, t0, t1");
                    self.emit_line("  snez t0, t0");
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::Not => { // !a
                    self.emit_line("  ld t0, 0(sp)");   // a
                    self.emit_line("  not t0, t0");     // Bitwise NOT (boolean için 0/1 dönüşümünde dikkat!)
                    self.emit_line("  snez t0, t0");    // Eğer 0 ise 1, değilse 0 (boolean NOT için)
                    self.emit_line("  sd t0, 0(sp)");
                }
                OpCode::Jump(target_idx) => {
                    // Etiket adı üretmek yerine, doğrudan Instruction Pointer (PC) göreceli atlama yapabiliriz
                    // Veya daha iyisi, IRGenerator'daki etiketleri buraya taşımak.
                    // Şimdilik basit bir etiket üretelim ve hedef olarak atlayalım.
                    // IRGenerator'ın yaptığı etiket düzeltmesi burada da gerekli olabilir.
                    // Ya da IRGenerator'dan gelen Jump(target_idx) gerçekten assembly'deki adresi ifade etmeli.
                    // Şimdilik varsayalım ki 'target_idx' bir satır numarası.
                    // Bu karmaşık bir kısım, en doğrusu Jump(target_label_name) olarak gelip burada etiketi kullanmak.
                    self.emit_line(&format!("  j .L_{}_{}", func_name, target_idx));
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  ld t0, 0(sp)"); // Yığından değeri al
                    self.emit_line("  addi sp, sp, 8"); // Pop et
                    // Eğer t0 sıfırsa (false), atla.
                    self.emit_line(&format!("  beqz t0, .L_{}_{}", func_name, target_idx));
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından a0-a7 registerlarına yükle (sağdan sola)
                    for i in 0..*arg_count {
                        let arg_reg = match i {
                            0 => "a0", 1 => "a1", 2 => "a2", 3 => "a3",
                            4 => "a4", 5 => "a5", 6 => "a6", 7 => "a7",
                            _ => { /* Fazla argümanlar için stack'ten doğrudan kullanım */ continue; }
                        };
                        // Argümanlar yığında ters sırada olduğu için (Push sırası)
                        // arg_count - 1 - i. argümanı al.
                        let stack_offset = (*arg_count - 1 - i) * 8;
                        self.emit_line(&format!("  ld {}, {}(sp)", arg_reg, stack_offset));
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  addi sp, sp, {}", arg_count * 8));

                    self.emit_line(&format!("  call {}", callee_name)); // Fonksiyonu çağır

                    // Dönüş değeri a0'da olur (eğer varsa), onu yığına it
                    // Basitlik için her zaman bir dönüş değeri olacağını varsayalım
                    self.emit_line("  addi sp, sp, -8");
                    self.emit_line("  sd a0, 0(sp)");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa a0'a yükle (yığının tepesinden)
                     if func.return_type != Type::Void {
                         self.emit_line("  ld a0, 0(sp)");
                         self.emit_line("  addi sp, sp, 8"); // Pop et
                     }
                    // Stack Frame Yıkımı (Basit)
                    self.emit_line(&format!("  addi sp, sp, {}", local_vars_size)); // Yerel değişken alanını geri al
                    self.emit_line("  ld ra, 8(sp)");    // ra'yı stack'ten geri yükle
                    self.emit_line("  ld s0, 0(sp)");    // s0'ı (eski fp) stack'ten geri yükle
                    self.emit_line("  addi sp, sp, 16"); // stack pointer'ı eski yerine geri getir
                    self.emit_line("  ret");             // Fonksiyondan dön (ra'ya atla)
                }
                OpCode::FunctionEnd => { /* Bu bir kontrol akışı yönergesi, kod üretmez */ }
                OpCode::SyscallPrintInt => {
                    self.emit_riscv64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_riscv64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_riscv64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        Ok(())
    }

    /// RISC-V 64 için ikili operatör kodu üretir.
    fn emit_binary_op(&mut self, instruction: &str) {
        self.emit_line("  ld t1, 0(sp)");   // Sağ operandı t1'e yükle
        self.emit_line("  addi sp, sp, 8"); // t1'i pop et
        self.emit_line("  ld t0, 0(sp)");   // Sol operandı t0'a yükle
        // self.emit_line("  addi sp, sp, 8"); // t0'ı pop et (sonra yeni sonucu push edeceğiz)

        self.emit_line(&format!("  {} t0, t0, t1", instruction)); // İşlemi yap (t0 = t0 op t1)
        // Sonucu tekrar yığına it
        // self.emit_line("  addi sp, sp, -8"); // Yer açmaya gerek yok, t0'ın üzerinde güncelledik.
        self.emit_line("  sd t0, 0(sp)"); // Yeni sonucu yığına kaydet (t0'ın yerine)
    }

    /// RISC-V 64 için karşılaştırma operatörü kodu üretir.
    fn emit_comparison_op(&mut self, instruction: &str) {
        self.emit_line("  ld t1, 0(sp)");   // Sağ operandı t1'e yükle
        self.emit_line("  addi sp, sp, 8"); // t1'i pop et
        self.emit_line("  ld t0, 0(sp)");   // Sol operandı t0'a yükle

        // Karşılaştırma sonucunu t0'a koy (0 veya 1)
        self.emit_line(&format!("  {} t0, t0, t1", instruction)); // Örn: slt t0, t0, t1 (t0 < t1 ise t0=1, değilse t0=0)
        self.emit_line("  sd t0, 0(sp)"); // Sonucu yığına kaydet
    }

    /// RISC-V 64 için sistem çağrısı ile çıktı üretir.
    /// `Sahne Karnal` sistem çağrılarını burada ele alıyoruz.
    fn emit_riscv64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  ld a0, 0(sp)");   // Yığından değeri a0'a yükle (argüman 1)
        self.emit_line("  addi sp, sp, 8"); // Değeri pop et

        let syscall_num = match ty {
            Type::Integer => 1, // `print_int` için syscall numarası (varsayımsal)
            Type::Boolean => 1, // `print_bool` için de aynı syscall'ı kullanabiliriz, 0/1 yazdırır
            Type::String => 4,  // `print_string` için syscall numarası (varsayımsal)
            _ => {
                return Err(CompilerError::CodeGen(CodeGenError::UnsupportedTypeForSyscall {
                    ty: ty.to_string(),
                    syscall_name: "print".to_string(),
                    line: 0, // Eksik bilgi, IRInstruction'da olmalıydı
                    column: 0,
                }));
            }
        };

        // Sahne Karnal sistem çağrıları (varsayımsal)
        // a7: syscall numarası
        // a0-a6: argümanlar
        self.emit_line(&format!("  li a7, {}", syscall_num)); // Syscall numarasını a7'ye yükle
        self.emit_line("  ecall"); // Sistem çağrısını tetikle

        Ok(())
    }

    /// Çıktı assembly'ye bir satır ekler.
    fn emit_line(&mut self, line: &str) {
        self.output_assembly.push_str(line);
        self.output_assembly.push_str("\n");
    }

    /// Sahne Karnal ve Karnal64 sistem çağrılarını yönetir.
    /// Bu metodlar, CodeGenerator'ın daha yüksek seviyeli bir katmanında çağrılabilir
    /// veya doğrudan `emit_riscv64_syscall_print` gibi metotlar içinde kullanılabilir.
    ///
    /// Örneğin, `emit_riscv64_syscall_print` içinde `self.target_config.opt_mode` kontrol edilebilir.
    ///
    /// ```rust
     fn emit_riscv64_syscall_print(&mut self, ty: Type) -> Result<()> {
    ///     // ... (değeri a0'a yükle)
    ///
         let syscall_num = match ty { /* ... */ };
    ///
         match self.target_config.opt_mode {
             OptimizationMode::KernelOnly => {
                 // Sadece Karnal64 syscall'ları (direkt a7 ve ecall)
                 self.emit_line(&format!("  li a7, {}", syscall_num));
                 self.emit_line("  ecall");
             }
             OptimizationMode::SahneAndKarnal => {
    ///             // Hem Sahne64 hem de Karnal64 syscall'ları.
    ///             // Sahne64'ün kendi syscall interface'i olabilir (örn. fn call_sahne_print_int(val: i64)).
                 // Bu durumda, bir C kitaplığına veya Sahne64 runtime'ına yönelik çağrı üretebiliriz.
                 // Örnek: Sahne64'ün kendi 'print_int' fonksiyonunu çağır.
                 match ty {
                     Type::Integer => {
                         self.emit_line("  call sahne_print_int"); // Sahne64 runtime fonksiyonu
                     }
                     // ... diğer türler
                     _ => { /* Fallback to Karnal64 or error */ }
                 }
             }
             _ => {
    ///             // Varsayılan olarak Karnal64 syscall'ları
                 self.emit_line(&format!("  li a7, {}", syscall_num));
                 self.emit_line("  ecall");
             }
         }
         Ok(())
     }
    /// ```
    /// Bu ayrım, derleyici seçeneklerine göre farklı çalışma zamanı kütüphanelerine veya çekirdek API'lerine
    /// bağlanma stratejilerini gerektirir.
    fn handle_syscall_mode(&mut self, _syscall_name: &str, _arg_regs: &[&str]) {
        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 özgü sistem çağrılarını doğrudan assembly olarak üretin.
                // Örn: `li a7, <syscall_num>`, `ecall`
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 sistem çağrıları arasında seçim yapın.
                // Bu, Sahne64'ün bir runtime kütüphanesi veya "ABI" (Application Binary Interface)
                // sağlamasını gerektirir.
                // Örn: `call sahne_lib_function` veya gerektiğinde direkt `ecall`.
            }
            _ => { /* Varsayılan olarak Karnal64 */ }
        }
    }
}
