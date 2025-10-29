// codegen_mips64.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// MIPS64 mimarisi için kod üreticisi
pub struct MIPS64CodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl MIPS64CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        MIPS64CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den MIPS64 assembly kodu üretir.
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
            self.generate_mips64_function(func)?;
        }

        self.emit_postlude();

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (.data, .text bölümleri vb.)
    fn emit_prelude(&mut self) {
        self.emit_line(".section .data"); // Veri bölümü
        self.emit_line(".align 3");       // 2^3 = 8 bayt hizalama (64-bit veri için)
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        // MIPS64'te özel bir postlude gerekmeyebilir.
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
                        // MIPS64'te stringler için .asciiz
                        self.emit_line(&format!("  .asciiz \"{}\"", s));
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

        self.emit_line(".section .text"); // Kod bölümü
        self.emit_line(".align 2");       // Fonksiyonlar için 2^2 = 4 bayt hizalama (Instruction size)
        Ok(())
    }

    /// Tek bir fonksiyonun MIPS64 assembly kodunu üretir.
    fn generate_mips64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".global {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".ent {}", func_name));    // Fonksiyon başlangıcı
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // MIPS64 ABI: $sp (r29) stack pointer, $ra (r31) dönüş adresi.
        // Genellikle $fp (r30/$s8) da kaydedilir.
        let frame_overhead = 16; // $ra ve $fp için yer
        let mut local_vars_size = func.next_local_offset * 8; // Yerel değişkenler için 8 bayt
        // Stack frame boyutu 16 bayt hizalı olmalı.
        let total_frame_size = ((local_vars_size + frame_overhead + 15) / 16) * 16;

        self.emit_line(&format!("  daddiu $sp, $sp, -{}", total_frame_size)); // Stack'i azalt
        self.emit_line(&format!("  sd $ra, {}($sp)", total_frame_size - 8)); // $ra'yı kaydet
        self.emit_line(&format!("  sd $fp, {}($sp)", total_frame_size - 16)); // $fp'yi kaydet
        self.emit_line("  daddiu $fp, $sp, 0"); // $fp'yi yeni $sp'ye ayarla

        // Parametreleri yerel değişken ofsetlerine kopyala
        // MIPS64 ABI: $a0-$a7 (r4-r11) argümanlar için kullanılır.
        let arg_regs = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"];
        for i in 0..func.parameter_count {
            if i < arg_regs.len() {
                let arg_reg = arg_regs[i];
                // Yerel değişken ofseti: $fp'ye göre pozitif ofset (kendi çerçevesinde)
                let offset_from_fp = (i * 8) as isize;
                self.emit_line(&format!("  sd {}, {}($fp)", arg_reg, offset_from_fp)); // Argümanı stack'e kaydet (store doubleword)
            } else {
                // Kalan argümanlar stack'ten alınır.
                // Bu durum daha karmaşıktır, şimdilik sadece ilk 8 argümanı destekleyelim.
                eprintln!("Uyarı: MIPS64'te 8'den fazla argüman şu an desteklenmiyor.");
            }
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            self.emit_line(&format!(".L_{}_{}:", func_name, i)); // Etiketler

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    // MIPS'te 64-bit sabitleri yüklemek için lui (load upper immediate) ve daddi (doubleword add immediate)
                    // veya doğrudan li (load immediate) kullanılabilir (pseudo-instruction).
                    self.emit_line(&format!("  li $t0, {}", val)); // Integer'ı t0'a yükle
                    self.emit_line("  daddiu $sp, $sp, -8"); // Stack'i azalt
                    self.emit_line("  sd $t0, 0($sp)");      // t0'ı stack'e it (store doubleword)
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  li $t0, {}", bool_val));
                    self.emit_line("  daddiu $sp, $sp, -8");
                    self.emit_line("  sd $t0, 0($sp)");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        // Global adresler için %hi/%lo veya gp-relative adresleme
                        self.emit_line(&format!("  lui $t0, %hi({})", label)); // Yüksek 16 bit
                        self.emit_line(&format!("  daddiu $t0, $t0, %lo({})", label)); // Düşük 16 bit
                        self.emit_line("  daddiu $sp, $sp, -8");
                        self.emit_line("  sd $t0, 0($sp)"); // t0'ı stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  ld $t0, {}($fp)", offset_from_fp)); // Yerel değişkeni t0'a yükle
                    self.emit_line("  daddiu $sp, $sp, -8");
                    self.emit_line("  sd $t0, 0($sp)"); // t0'ı stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  ld $t0, 0($sp)"); // Stack'ten değeri t0'a al
                    self.emit_line("  daddiu $sp, $sp, 8"); // Stack'ten pop et
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  sd $t0, {}($fp)", offset_from_fp)); // t0'ı yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  lui $t0, %hi({})", label));
                        self.emit_line(&format!("  daddiu $t0, $t0, %lo({})", label));
                        self.emit_line("  ld $t0, 0($t0)"); // Global değişkenin değerini t0'a yükle
                        self.emit_line("  daddiu $sp, $sp, -8");
                        self.emit_line("  sd $t0, 0($sp)");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  ld $t0, 0($sp)"); // Stack'ten değeri t0'a al
                    self.emit_line("  daddiu $sp, $sp, 8"); // Stack'ten pop et
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  lui $t1, %hi({})", label)); // Geçici bir kaydedici kullan
                        self.emit_line(&format!("  daddiu $t1, $t1, %lo({})", label));
                        self.emit_line("  sd $t0, 0($t1)"); // t0'ı global değişkene kaydet
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_mips64_binary_op("dadd"), // Doubleword add
                OpCode::Sub => self.emit_mips64_binary_op("dsub"), // Doubleword subtract
                OpCode::Mul => self.emit_mips64_binary_op("dmul"), // Doubleword multiply
                OpCode::Div => self.emit_mips64_binary_op("ddiv"), // Doubleword signed divide
                OpCode::Eq => self.emit_mips64_comparison_op("beq", "bne"),
                OpCode::Ne => self.emit_mips64_comparison_op("bne", "beq"),
                OpCode::Lt => self.emit_mips64_comparison_op("blt", "bge"),
                OpCode::Le => self.emit_mips64_comparison_op("ble", "bgt"),
                OpCode::Gt => self.emit_mips64_comparison_op("bgt", "ble"),
                OpCode::Ge => self.emit_mips64_comparison_op("bge", "blt"),
                OpCode::And => self.emit_mips64_binary_op("and"),
                OpCode::Or => self.emit_mips64_binary_op("or"),
                OpCode::Not => {
                    self.emit_line("  ld $t0, 0($sp)"); // Değeri t0'a al
                    self.emit_line("  sltiu $t0, $t0, 1"); // Eğer t0 < 1 (yani 0 ise) t0'a 1, değilse 0 yaz
                    self.emit_line("  sd $t0, 0($sp)"); // Sonucu stack'e kaydet
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  b .L_{}_{}", func_name, target_idx));
                    self.emit_line("  nop"); // Gecikme slotu (branch delay slot)
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  ld $t0, 0($sp)"); // Koşulu t0'a al
                    self.emit_line("  daddiu $sp, $sp, 8"); // Pop et
                    self.emit_line(&format!("  beq $t0, $zero, .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                    self.emit_line("  nop"); // Gecikme slotu
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından $a0-$a7 kaydedicilerine yükle (sağdan sola)
                    let arg_input_regs = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"];
                    for i in 0..*arg_count {
                        if i < arg_input_regs.len() {
                            let arg_reg = arg_input_regs[i];
                            // Argümanlar yığında ters sırada olduğu için
                            let stack_offset = (*arg_count - 1 - i) * 8;
                            self.emit_line(&format!("  ld {}, {}($sp)", arg_reg, stack_offset + 8)); // mevcut stack'in üstü + 8
                        } else {
                            // MIPS64 ABI'sına göre ilk 8 argüman kaydedicilerde, diğerleri stack'te.
                            // Burada karmaşıklığı artırmamak adına sadece ilk 8'i destekliyoruz.
                            eprintln!("Uyarı: MIPS64'te 8'den fazla argüman şu an desteklenmiyor.");
                        }
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  daddiu $sp, $sp, {}", arg_count * 8));

                    self.emit_line(&format!("  jal {}", callee_name)); // Fonksiyonu çağır (Jump and Link)
                    self.emit_line("  nop"); // Gecikme slotu

                    // Dönüş değeri $v0'da (r2) olur, onu yığına it
                    self.emit_line("  daddiu $sp, $sp, -8");
                    self.emit_line("  sd $v0, 0($sp)");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa $v0'a yükle (yığının tepesinden)
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  ld $v0, 8($sp)");
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    self.emit_line(&format!("  ld $ra, {}($sp)", total_frame_size - 8)); // $ra'yı geri yükle
                    self.emit_line(&format!("  ld $fp, {}($sp)", total_frame_size - 16)); // $fp'yi geri yükle
                    self.emit_line(&format!("  daddiu $sp, $sp, {}", total_frame_size)); // Stack'i geri al
                    self.emit_line("  jr $ra"); // Dönüş adresine atla (Jump Register)
                    self.emit_line("  nop");    // Gecikme slotu
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_mips64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_mips64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_mips64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".end {}", func_name)); // Fonksiyon bitişi
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// MIPS64 için ikili operatör kodu üretir.
    fn emit_mips64_binary_op(&mut self, instruction: &str) {
        self.emit_line("  ld $t1, 0($sp)"); // Sağ operandı t1'e yükle
        self.emit_line("  daddiu $sp, $sp, 8"); // Pop et
        self.emit_line("  ld $t0, 0($sp)"); // Sol operandı t0'a yükle
        self.emit_line(&format!("  {} $t0, $t0, $t1", instruction)); // İşlemi yap ($t0 = $t0 op $t1)
        self.emit_line("  sd $t0, 0($sp)"); // Sonucu stack'e kaydet
    }

    /// MIPS64 için karşılaştırma operatörü kodu üretir.
    /// `true_branch_instr`: koşul doğruysa atlama yönergesi (örn: beq)
    /// `false_branch_instr`: koşul yanlışsa atlama yönergesi (örn: bne)
    fn emit_mips64_comparison_op(&mut self, true_branch_instr: &str, false_branch_instr: &str) {
        self.emit_line("  ld $t1, 0($sp)"); // Sağ operandı t1'e
        self.emit_line("  daddiu $sp, $sp, 8"); // Pop et
        self.emit_line("  ld $t0, 0($sp)"); // Sol operandı t0'a

        let true_label = String::from_format_args!(".L_true_{}", self.next_string_id);
        let end_label = String::from_format_args!(".L_end_{}", self.next_string_id);
        self.next_string_id += 1;

        self.emit_line(&format!("  {} $t0, $t1, {}", true_branch_instr, true_label)); // Koşul doğruysa true_label'a atla
        self.emit_line("  nop"); // Gecikme slotu

        self.emit_line("  li $t0, 0"); // $t0 = 0 (False)
        self.emit_line(&format!("  b {}", end_label)); // Atla
        self.emit_line("  nop"); // Gecikme slotu

        self.emit_line(&format!("{}:", true_label));
        self.emit_line("  li $t0, 1"); // $t0 = 1 (True)

        self.emit_line(&format!("{}:", end_label));
        self.emit_line("  sd $t0, 0($sp)"); // Sonucu stack'e kaydet
    }

    /// MIPS64 için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_mips64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  ld $a0, 0($sp)"); // Yığından değeri $a0'a yükle (argüman 1)
        self.emit_line("  daddiu $sp, $sp, 8"); // Pop et

        // Linux MIPS64 ABI'de write syscall numarası 64'tür.
        let syscall_num = 64;

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                // write syscall: $a0=fd (1 for stdout), $a1=buf, $a2=count
                self.emit_line(&format!("  li $v0, {}", syscall_num)); // Syscall numarası $v0'a
                self.emit_line("  li $a0, 1");                         // stdout (fd=1)
                self.emit_line("  move $a1, $a0");                      // $a0'daki değeri $a1'e taşı (buf - değerin kendisi)
                self.emit_line("  li $a2, 8");                         // 8 bayt yazdır (long size, varsayımsal)
                                                                       // NOTE: Integer/Boolean için, sayıyı string'e çevirmesi gerekir
                                                                       // Bu basitleştirilmiş bir yaklaşımdır.
                self.emit_line("  syscall"); // Sistem çağrısını tetikle
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 arasında seçim yapın.
                match ty {
                    Type::Integer => {
                        self.emit_line("  jal sahne_print_int"); // Sahne64 runtime fonksiyonu
                        self.emit_line("  nop"); // Gecikme slotu
                    }
                    Type::Boolean => {
                         self.emit_line("  jal sahne_print_bool");
                         self.emit_line("  nop"); // Gecikme slotu
                    }
                    Type::String => {
                        self.emit_line("  jal sahne_print_string");
                        self.emit_line("  nop"); // Gecikme slotu
                    }
                    _ => {
                        // Fallback to Karnal64 syscall
                        self.emit_line(&format!("  li $v0, {}", syscall_num));
                        self.emit_line("  li $a0, 1");
                        self.emit_line("  move $a1, $a0");
                        self.emit_line("  li $a2, 8");
                        self.emit_line("  syscall");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line(&format!("  li $v0, {}", syscall_num));
                self.emit_line("  li $a0, 1");
                self.emit_line("  move $a1, $a0");
                self.emit_line("  li $a2, 8");
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
