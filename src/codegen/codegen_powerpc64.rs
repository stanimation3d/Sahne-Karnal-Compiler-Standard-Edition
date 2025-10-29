// codegen_powerpc64.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// PowerPC64 mimarisi için kod üreticisi
pub struct PowerPC64CodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl PowerPC64CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        PowerPC64CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den PowerPC64 assembly kodu üretir.
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
            self.generate_powerpc64_function(func)?;
        }

        self.emit_postlude();

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (.data, .text bölümleri vb.)
    fn emit_prelude(&mut self) {
        self.emit_line(".section \".data\""); // Veri bölümü
        self.emit_line(".align 8");          // 8-bayt hizalama (64-bit veri için)
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        // PowerPC64'te özel bir postlude gerekmeyebilir.
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
                        // PowerPC64'te stringler için .asciz
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

        self.emit_line(".section \".text\""); // Kod bölümü
        self.emit_line(".align 4");           // Fonksiyonlar için 4-bayt hizalama (Instruction size)
        Ok(())
    }

    /// Tek bir fonksiyonun PowerPC64 assembly kodunu üretir.
    fn generate_powerpc64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".global {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".type {}, @function", func_name)); // Fonksiyon tipini belirt
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // Linux ELFv2 ABI: Min stack frame size = 48 bytes (caller's save area + LR + CR + reserved)
        // This includes:
        //  8 bytes for Back-Chain Pointer (previous stack frame)
        //  8 bytes for LR save area
        //  8 bytes for CR save area
        //  8 bytes for Reserved
        //  24 bytes for general purpose registers (r3-r10) on entry
        // Total caller's save area is 48 bytes.
        let min_frame_overhead = 48;
        let mut local_vars_size = func.next_local_offset * 8; // Yerel değişkenler için 8 bayt
        // Stack frame boyutu 16 bayt hizalı olmalı.
        let total_frame_size = ((local_vars_size + min_frame_overhead + 15) / 16) * 16;

        // Save Link Register (LR) and Condition Register (CR) if necessary
        // Linux ABI usually stores LR at 16(r1) and CR at 24(r1) (relative to caller's SP)
        // For current frame: LR will be at current_SP + 16, CR at current_SP + 24
        // r1: stack pointer
        self.emit_line(&format!("  mflr r0")); // LR'ı r0'a taşı
        self.emit_line(&format!("  std r0, {}(r1)", min_frame_overhead - 32)); // r0'ı stack'e kaydet (LR)
        self.emit_line(&format!("  stdu r1, r1, -{}", total_frame_size)); // Stack pointer'ı azalt ve önceki SP'yi kaydet (back-chain pointer)

        // Parametreleri yerel değişken ofsetlerine kopyala
        // PowerPC ABI: r3-r10 argümanlar için kullanılır.
        let arg_regs = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]; // İlk 8 argüman
        for i in 0..func.parameter_count {
            if i < arg_regs.len() {
                let arg_reg = arg_regs[i];
                // Yerel değişken ofseti: r1 (SP) + total_frame_size (frame'in üstü) + ofset (local_vars_size'dan sonra)
                let offset_from_sp = (i * 8) as isize + total_frame_size as isize;
                self.emit_line(&format!("  std {}, {}(r1)", arg_reg, offset_from_sp)); // Argümanı stack'e kaydet
            } else {
                // Kalan argümanlar stack'ten alınır.
                // Bu durum daha karmaşıktır, şimdilik sadece ilk 8 argümanı destekleyelim.
                eprintln!("Uyarı: PowerPC64'te 8'den fazla argüman şu an desteklenmiyor.");
            }
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            self.emit_line(&format!(".L_{}_{}:", func_name, i)); // Etiketler

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  li r0, {}", val)); // Integer'ı r0'a yükle (64-bit için lis/ori veya load immediate)
                    self.emit_line("  stdu r0, r1, -8"); // r0'ı stack'e it (store doubleword update)
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  li r0, {}", bool_val));
                    self.emit_line("  stdu r0, r1, -8");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        // PowerPC'de global verilere erişim için .toc (Table of Contents) kullanılır
                        // Veya doğrudan PC-relative yükleme (lis/addi).
                        // Burada .toc'yi basitleştirerek direkt adresleme yapacağız (linker'ın hallettiği varsayımıyla).
                        // Gerçek bir derleyici için .toc/global entry point erişimi daha karmaşıktır.
                        self.emit_line(&format!("  addis r0, r2, .L{}@ha", label)); // Yüksek 16 bit
                        self.emit_line(&format!("  addi r0, r0, .L{}@l", label));   // Düşük 16 bit
                        self.emit_line("  stdu r0, r1, -8"); // r0'ı stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    // Yerel değişken ofseti: r1 (SP) + total_frame_size (frame'in üstü) + ofset
                    let offset_from_sp = (offset * 8) as isize + total_frame_size as isize;
                    self.emit_line(&format!("  ld r0, {}(r1)", offset_from_sp)); // Yerel değişkeni r0'a yükle
                    self.emit_line("  stdu r0, r1, -8"); // r0'ı stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  ld r0, 8(r1)"); // Stack'ten değeri r0'a al
                    self.emit_line("  addi r1, r1, 8"); // Stack'ten pop et
                    let offset_from_sp = (offset * 8) as isize + total_frame_size as isize;
                    self.emit_line(&format!("  std r0, {}(r1)", offset_from_sp)); // r0'ı yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  addis r0, r2, .L{}@ha", label));
                        self.emit_line(&format!("  addi r0, r0, .L{}@l", label));
                        self.emit_line("  ld r0, 0(r0)"); // Global değişkenin değerini r0'a yükle
                        self.emit_line("  stdu r0, r1, -8");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  ld r0, 8(r1)"); // Stack'ten değeri r0'a al
                    self.emit_line("  addi r1, r1, 8"); // Stack'ten pop et
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  addis r11, r2, .L{}@ha", label)); // Geçici bir kaydedici kullan
                        self.emit_line(&format!("  addi r11, r11, .L{}@l", label));
                        self.emit_line("  std r0, 0(r11)"); // r0'ı global değişkene kaydet
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_powerpc64_binary_op("add"),
                OpCode::Sub => self.emit_powerpc64_binary_op("subf"), // Sub From
                OpCode::Mul => self.emit_powerpc64_binary_op("mulld"), // Multiply Lower Doubleword
                OpCode::Div => self.emit_powerpc64_binary_op("divd"), // Signed Divide Doubleword
                OpCode::Eq => self.emit_powerpc64_comparison_op("cr0", "beq", "bne"), // Condition Register (CR0) Field
                OpCode::Ne => self.emit_powerpc64_comparison_op("cr0", "bne", "beq"),
                OpCode::Lt => self.emit_powerpc64_comparison_op("cr0", "blt", "bge"),
                OpCode::Le => self.emit_powerpc64_comparison_op("cr0", "ble", "bgt"),
                OpCode::Gt => self.emit_powerpc64_comparison_op("cr0", "bgt", "ble"),
                OpCode::Ge => self.emit_powerpc64_comparison_op("cr0", "bge", "blt"),
                OpCode::And => self.emit_powerpc64_binary_op("and"),
                OpCode::Or => self.emit_powerpc64_binary_op("or"),
                OpCode::Not => {
                    self.emit_line("  ld r0, 8(r1)"); // Değeri r0'a al
                    self.emit_line("  cmpdi r0, 0");  // r0'ı 0 ile karşılaştır
                    self.emit_line("  li r0, 0");     // r0 = 0 (False varsayalım)
                    self.emit_line("  bne+ 0, .L_not_end_{}", self.next_string_id); // Eğer eşit değilse 0 kal
                    self.emit_line("  li r0, 1");     // Eşitse r0 = 1 (True)
                    self.emit_line(&format!(".L_not_end_{}:", self.next_string_id));
                    self.next_string_id += 1;
                    self.emit_line("  std r0, 8(r1)"); // Sonucu stack'e kaydet
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  b .L_{}_{}", func_name, target_idx));
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  ld r0, 8(r1)"); // Koşulu r0'a al
                    self.emit_line("  addi r1, r1, 8"); // Pop et
                    self.emit_line("  cmpdi r0, 0");    // r0'ı 0 ile karşılaştır
                    self.emit_line(&format!("  beq .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından r3-r10 kaydedicilerine yükle (sağdan sola)
                    let arg_input_regs = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"];
                    for i in 0..*arg_count {
                        if i < arg_input_regs.len() {
                            let arg_reg = arg_input_regs[i];
                            // Argümanlar yığında ters sırada olduğu için
                            let stack_offset = (*arg_count - 1 - i) * 8;
                            self.emit_line(&format!("  ld {}, {}(r1)", arg_reg, stack_offset + 8)); // 8(r1) current stack top
                        } else {
                            eprintln!("Uyarı: PowerPC64'te 8'den fazla argüman şu an desteklenmiyor.");
                        }
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  addi r1, r1, {}", arg_count * 8));

                    // Link Register'ı (LR) kaydetmek gerekli.
                    self.emit_line(&format!("  bl {}", callee_name)); // Fonksiyonu çağır (Branch with Link)

                    // Dönüş değeri r3'te olur, onu yığına it
                    self.emit_line("  stdu r3, r1, -8");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa r3'e yükle (yığının tepesinden)
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  ld r3, 8(r1)");
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    self.emit_line(&format!("  addi r1, r1, {}", total_frame_size)); // Stack'i geri al
                    self.emit_line(&format!("  ld r0, {}(r1)", min_frame_overhead - 32)); // LR'ı geri yükle
                    self.emit_line("  mtlr r0"); // r0'daki değeri LR'a taşı
                    self.emit_line("  blr");     // Dönüş adresine atla (Branch to Link Register)
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_powerpc64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_powerpc64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_powerpc64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// PowerPC64 için ikili operatör kodu üretir.
    fn emit_powerpc64_binary_op(&mut self, instruction: &str) {
        self.emit_line("  ld r4, 8(r1)"); // Sağ operandı r4'e yükle (SP+8'de)
        self.emit_line("  addi r1, r1, 8"); // Pop et
        self.emit_line("  ld r3, 8(r1)"); // Sol operandı r3'e yükle
        self.emit_line(&format!("  {} r3, r3, r4", instruction)); // İşlemi yap (r3 = r3 op r4)
        self.emit_line("  stdu r3, r1, -8"); // Sonucu stack'e kaydet
    }

    /// PowerPC64 için karşılaştırma operatörü kodu üretir.
    /// `cr_field`: Condition Register alanı (örneğin "cr0")
    /// `true_branch_instr`: koşul doğruysa atlama yönergesi (örn: beq)
    /// `false_branch_instr`: koşul yanlışsa atlama yönergesi (örn: bne)
    fn emit_powerpc64_comparison_op(&mut self, cr_field: &str, true_branch_instr: &str, false_branch_instr: &str) {
        self.emit_line("  ld r4, 8(r1)"); // Sağ operandı r4'e
        self.emit_line("  addi r1, r1, 8"); // Pop et
        self.emit_line("  ld r3, 8(r1)"); // Sol operandı r3'e

        self.emit_line(&format!("  cmpd {}, r3, r4", cr_field)); // r3 ile r4'ü karşılaştır

        let true_label = String::from_format_args!(".L_true_{}", self.next_string_id);
        let end_label = String::from_format_args!(".L_end_{}", self.next_string_id);
        self.next_string_id += 1;

        self.emit_line(&format!("  {} {}", true_branch_instr, true_label)); // Koşul doğruysa true_label'a atla
        self.emit_line("  li r0, 0"); // r0 = 0 (False)
        self.emit_line(&format!("  b {}", end_label)); // Atla

        self.emit_line(&format!("{}:", true_label));
        self.emit_line("  li r0, 1"); // r0 = 1 (True)

        self.emit_line(&format!("{}:", end_label));
        self.emit_line("  stdu r0, r1, -8"); // Sonucu stack'e kaydet
    }

    /// PowerPC64 için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_powerpc64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  ld r3, 8(r1)"); // Yığından değeri r3'e yükle (argüman 1)
        self.emit_line("  addi r1, r1, 8"); // Pop et

        // Linux PowerPC64 ABI'de write syscall numarası 64'tür.
        let syscall_num = 64;

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                // write syscall: r3=fd (1 for stdout), r4=buf, r5=count
                self.emit_line(&format!("  li r0, {}", syscall_num)); // Syscall numarası r0'a
                self.emit_line("  li r3, 1");                         // stdout (fd=1)
                self.emit_line("  mr r4, r3");                        // r3'teki değeri r4'e taşı (buf - değerin kendisi)
                self.emit_line("  li r5, 8");                         // 8 bayt yazdır (long size, varsayımsal)
                                                                      // NOTE: Integer/Boolean için, sayıyı string'e çevirmesi gerekir.
                                                                      // Bu basitleştirilmiş bir yaklaşımdır.
                self.emit_line("  sc"); // Sistem çağrısını tetikle
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 arasında seçim yapın.
                match ty {
                    Type::Integer => {
                        self.emit_line("  bl sahne_print_int"); // Sahne64 runtime fonksiyonu
                    }
                    Type::Boolean => {
                         self.emit_line("  bl sahne_print_bool");
                    }
                    Type::String => {
                        self.emit_line("  bl sahne_print_string");
                    }
                    _ => {
                        // Fallback to Karnal64 syscall
                        self.emit_line(&format!("  li r0, {}", syscall_num));
                        self.emit_line("  li r3, 1");
                        self.emit_line("  mr r4, r3");
                        self.emit_line("  li r5, 8");
                        self.emit_line("  sc");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line(&format!("  li r0, {}", syscall_num));
                self.emit_line("  li r3, 1");
                self.emit_line("  mr r4, r3");
                self.emit_line("  li r5, 8");
                self.emit_line("  sc");
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
