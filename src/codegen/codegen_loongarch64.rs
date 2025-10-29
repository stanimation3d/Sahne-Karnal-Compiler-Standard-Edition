// codegen_loongarch64.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// LoongArch64 mimarisi için kod üreticisi
pub struct LoongArch64CodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl LoongArch64CodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        LoongArch64CodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den LoongArch64 assembly kodu üretir.
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
            self.generate_loongarch64_function(func)?;
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
        // LoongArch64'te özel bir postlude gerekmeyebilir.
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
                        // LoongArch64'te stringler için .asciz
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

    /// Tek bir fonksiyonun LoongArch64 assembly kodunu üretir.
    fn generate_loongarch64_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".global {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".type {}, @function", func_name)); // Fonksiyon tipini belirt
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // LoongArch64 ABI: sp (r1) kullanılır. lr (r21) kaydedilmesi gerekir.
        let frame_overhead = 16; // lr (r21) ve r22 (örneğin callee-saved) için yer
        let mut local_vars_size = func.next_local_offset * 8; // Yerel değişkenler için 8 bayt
        // Stack frame boyutu 16 bayt hizalı olmalı.
        let total_frame_size = ((local_vars_size + frame_overhead + 15) / 16) * 16;

        self.emit_line(&format!("  addi.d $sp, $sp, -{}", total_frame_size)); // Stack'i azalt
        self.emit_line(&format!("  st.d $ra, {}($sp)", total_frame_size - 8)); // $ra'yı (r21) kaydet
        self.emit_line(&format!("  st.d $fp, {}($sp)", total_frame_size - 16)); // $fp'yi (r22) kaydet (eğer kullanılıyorsa)
        self.emit_line("  addi.d $fp, $sp, 0"); // $fp'yi yeni $sp'ye ayarla

        // Parametreleri yerel değişken ofsetlerine kopyala
        // LoongArch64 ABI: $a0-$a5 (r4-r9) argümanlar için kullanılır.
        let arg_regs = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5"]; // r4-r9
        for i in 0..func.parameter_count {
            if i < arg_regs.len() {
                let arg_reg = arg_regs[i];
                // Yerel değişken ofseti: $fp'ye göre pozitif ofset (kendi çerçevesinde)
                let offset_from_fp = (i * 8) as isize;
                self.emit_line(&format!("  st.d {}, {}($fp)", arg_reg, offset_from_fp)); // Argümanı stack'e kaydet (store doubleword)
            } else {
                // Kalan argümanlar stack'ten alınır.
                // Bu durum daha karmaşıktır, şimdilik sadece ilk 6 argümanı destekleyelim.
                eprintln!("Uyarı: LoongArch64'te 6'dan fazla argüman şu an desteklenmiyor.");
            }
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            self.emit_line(&format!(".L_{}_{}:", func_name, i)); // Etiketler

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  li.d $t0, {}", val)); // Integer'ı t0'a yükle (load immediate doubleword)
                    self.emit_line("  st.d $t0, -8($sp)"); // t0'ı stack'e it (store doubleword, pre-decrement)
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  li.d $t0, {}", bool_val));
                    self.emit_line("  st.d $t0, -8($sp)");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        // Global adresler için %pc_hi/%pc_low kullanabiliriz
                        self.emit_line(&format!("  pcalau12i $t0, %pc_hi20({})", label)); // Yüksek 20 bit
                        self.emit_line(&format!("  addi.d $t0, $t0, %pc_low12({})", label)); // Düşük 12 bit
                        self.emit_line("  st.d $t0, -8($sp)"); // t0'ı stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  ld.d $t0, {}($fp)", offset_from_fp)); // Yerel değişkeni t0'a yükle
                    self.emit_line("  st.d $t0, -8($sp)"); // t0'ı stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  ld.d $t0, 0($sp)"); // Stack'ten değeri t0'a al
                    self.emit_line("  addi.d $sp, $sp, 8"); // Stack'ten pop et
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  st.d $t0, {}($fp)", offset_from_fp)); // t0'ı yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  pcalau12i $t0, %pc_hi20({})", label));
                        self.emit_line(&format!("  addi.d $t0, $t0, %pc_low12({})", label));
                        self.emit_line("  ld.d $t0, 0($t0)"); // Global değişkenin değerini t0'a yükle
                        self.emit_line("  st.d $t0, -8($sp)");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  ld.d $t0, 0($sp)"); // Stack'ten değeri t0'a al
                    self.emit_line("  addi.d $sp, $sp, 8"); // Stack'ten pop et
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  pcalau12i $t1, %pc_hi20({})", label)); // Geçici bir kaydedici kullan
                        self.emit_line(&format!("  addi.d $t1, $t1, %pc_low12({})", label));
                        self.emit_line("  st.d $t0, 0($t1)"); // t0'ı global değişkene kaydet
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_loongarch64_binary_op("add.d"),
                OpCode::Sub => self.emit_loongarch64_binary_op("sub.d"),
                OpCode::Mul => self.emit_loongarch64_binary_op("mul.d"),
                OpCode::Div => self.emit_loongarch64_binary_op("div.d"), // İşaretli bölme
                OpCode::Eq => self.emit_loongarch64_comparison_op("ceqi.d", "b"),
                OpCode::Ne => self.emit_loongarch64_comparison_op("cnei.d", "b"),
                OpCode::Lt => self.emit_loongarch64_comparison_op("clti.d", "b"),
                OpCode::Le => self.emit_loongarch64_comparison_op("clei.d", "b"),
                OpCode::Gt => self.emit_loongarch64_comparison_op("cgti.d", "b"),
                OpCode::Ge => self.emit_loongarch64_comparison_op("cgei.d", "b"),
                OpCode::And => self.emit_loongarch64_binary_op("and"),
                OpCode::Or => self.emit_loongarch64_binary_op("or"),
                OpCode::Not => {
                    self.emit_line("  ld.d $t0, 0($sp)"); // Değeri t0'a al
                    self.emit_line("  xor $t0, $t0, 1");  // XOR ile 1 (true) ise 0 (false), 0 (false) ise 1 (true) yap
                    self.emit_line("  st.d $t0, 0($sp)"); // Sonucu stack'e kaydet
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  b .L_{}_{}", func_name, target_idx));
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  ld.d $t0, 0($sp)"); // Koşulu t0'a al
                    self.emit_line("  addi.d $sp, $sp, 8"); // Pop et
                    self.emit_line(&format!("  beqz $t0, .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından $a0-$a5 kaydedicilerine yükle (sağdan sola)
                    let arg_input_regs = ["$a0", "$a1", "$a2", "$a3", "$a4", "$a5"]; // r4-r9
                    for i in 0..*arg_count {
                        if i < arg_input_regs.len() {
                            let arg_reg = arg_input_regs[i];
                            // Argümanlar yığında ters sırada olduğu için
                            let stack_offset = (*arg_count - 1 - i) * 8;
                            self.emit_line(&format!("  ld.d {}, {}($sp)", arg_reg, stack_offset + 8)); // mevcut stack'in üstü + 8
                        } else {
                            eprintln!("Uyarı: LoongArch64'te 6'dan fazla argüman şu an desteklenmiyor.");
                        }
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  addi.d $sp, $sp, {}", arg_count * 8));

                    self.emit_line(&format!("  bl {}", callee_name)); // Fonksiyonu çağır (Branch and Link)

                    // Dönüş değeri $a0'da (r4) olur, onu yığına it
                    self.emit_line("  st.d $a0, -8($sp)");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa $a0'a yükle (yığının tepesinden)
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  ld.d $a0, 8($sp)");
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    self.emit_line(&format!("  ld.d $ra, {}($sp)", total_frame_size - 8)); // $ra'yı geri yükle
                    self.emit_line(&format!("  ld.d $fp, {}($sp)", total_frame_size - 16)); // $fp'yi geri yükle
                    self.emit_line(&format!("  addi.d $sp, $sp, {}", total_frame_size)); // Stack'i geri al
                    self.emit_line("  jr $ra");     // Dönüş adresine atla (Jump Register)
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_loongarch64_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_loongarch64_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_loongarch64_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// LoongArch64 için ikili operatör kodu üretir.
    fn emit_loongarch64_binary_op(&mut self, instruction: &str) {
        self.emit_line("  ld.d $t1, 0($sp)"); // Sağ operandı t1'e yükle
        self.emit_line("  addi.d $sp, $sp, 8"); // Pop et
        self.emit_line("  ld.d $t0, 0($sp)"); // Sol operandı t0'a yükle
        self.emit_line(&format!("  {} $t0, $t0, $t1", instruction)); // İşlemi yap (t0 = t0 op t1)
        self.emit_line("  st.d $t0, 0($sp)"); // Sonucu stack'e kaydet
    }

    /// LoongArch64 için karşılaştırma operatörü kodu üretir.
    /// `compare_instr`: Karşılaştırma yönergesi (örn: ceqi.d, clti.d)
    /// `branch_instr`: Dallanma yönergesi (örn: b)
    fn emit_loongarch64_comparison_op(&mut self, compare_instr: &str, branch_instr: &str) {
        self.emit_line("  ld.d $t1, 0($sp)"); // Sağ operandı t1'e
        self.emit_line("  addi.d $sp, $sp, 8"); // Pop et
        self.emit_line("  ld.d $t0, 0($sp)"); // Sol operandı t0'a

        self.emit_line(&format!("  {} $t0, $t0, $t1", compare_instr)); // Karşılaştırma yap (t0'a 0 veya 1 yazılır)

        // LoongArch'ta compare yönergeleri sonucu doğrudan hedeflenen kaydediciye yazar (0 veya 1).
        // Bu yüzden ayrıca bir karşılaştırma yapmaya gerek kalmaz.
        self.emit_line("  st.d $t0, 0($sp)"); // Sonucu stack'e kaydet
    }

    /// LoongArch64 için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_loongarch64_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  ld.d $a0, 0($sp)"); // Yığından değeri $a0'a yükle (argüman 1)
        self.emit_line("  addi.d $sp, $sp, 8"); // Pop et

        // Linux LoongArch64 ABI'de write syscall numarası 64'tür.
        let syscall_num = 64;

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                // write syscall: $a0=fd (1 for stdout), $a1=buf, $a2=count
                self.emit_line(&format!("  li.d $a7, {}", syscall_num)); // Syscall numarası $a7'ye (veya r11'e)
                self.emit_line("  li.d $a0, 1");                       // stdout (fd=1)
                self.emit_line("  ori $a1, $a0, 0");                   // $a0'daki değeri $a1'e taşı (buf - değerin kendisi)
                self.emit_line("  li.d $a2, 8");                       // 8 bayt yazdır (long size, varsayımsal)
                                                                      // NOTE: Integer/Boolean için, sayıyı string'e çevirmesi gerekir
                                                                      // Bu basitleştirilmiş bir yaklaşımdır.
                self.emit_line("  syscall 0x0"); // Sistem çağrısını tetikle
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
                        self.emit_line(&format!("  li.d $a7, {}", syscall_num));
                        self.emit_line("  li.d $a0, 1");
                        self.emit_line("  ori $a1, $a0, 0");
                        self.emit_line("  li.d $a2, 8");
                        self.emit_line("  syscall 0x0");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line(&format!("  li.d $a7, {}", syscall_num));
                self.emit_line("  li.d $a0, 1");
                self.emit_line("  ori $a1, $a0, 0");
                self.emit_line("  li.d $a2, 8");
                self.emit_line("  syscall 0x0");
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
