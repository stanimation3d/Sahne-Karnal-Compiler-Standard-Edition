// codegen_openrisc.rs
#![no_std]

use crate::ir::{IRModule, IRFunction, OpCode, IRInstruction};
use crate::target::{TargetConfig, OptimizationMode, TargetArch};
use crate::type_system::Type;
use crate::error::{CompilerError, Result, CodeGenError};
use sahne64::utils::{Vec, String, HashMap};
use sahne64::{print, println, eprintln};

/// OpenRISC mimarisi için kod üreticisi
pub struct OpenRISCCodeGenerator {
    target_config: TargetConfig,
    output_assembly: String,
    global_variable_addresses: HashMap<String, String>, // Global değişken adı -> Etiket adı
    string_literals: HashMap<String, String>,          // String içeriği -> Etiket adı
    next_string_id: usize,
    /// Fonksiyon bazında etiketlerin gerçek adreslerini tutarız.
    function_labels: HashMap<String, usize>, // Etiket adı -> IRInstruction listesindeki indeks (yönerge adresi)
}

impl OpenRISCCodeGenerator {
    pub fn new(target_config: TargetConfig) -> Self {
        OpenRISCCodeGenerator {
            target_config,
            output_assembly: String::new(),
            global_variable_addresses: HashMap::new(),
            string_literals: HashMap::new(),
            next_string_id: 0,
            function_labels: HashMap::new(),
        }
    }

    /// IRModule'den OpenRISC assembly kodu üretir.
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
            self.generate_openrisc_function(func)?;
        }

        self.emit_postlude();

        Ok(self.output_assembly.clone())
    }

    /// Assembly dosyasının başlangıcını yazar (.data, .text bölümleri vb.)
    fn emit_prelude(&mut self) {
        self.emit_line(".section .data"); // Veri bölümü
        self.emit_line(".align 8");       // 8-bayt hizalama (64-bit veri için)
    }

    /// Assembly dosyasının bitişini yazar
    fn emit_postlude(&mut self) {
        // OpenRISC'te özel bir postlude gerekmeyebilir.
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
                        // OpenRISC'te stringler için .asciz
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

        self.emit_line(".section .text"); // Kod bölümü
        self.emit_line(".align 8");       // Fonksiyonlar için 8-bayt hizalama
        Ok(())
    }

    /// Tek bir fonksiyonun OpenRISC assembly kodunu üretir.
    fn generate_openrisc_function(&mut self, func: &IRFunction) -> Result<()> {
        let func_name = &func.name;
        self.emit_line(&format!(".global {}", func_name)); // Fonksiyonu global yap
        self.emit_line(&format!(".type {}, @function", func_name)); // Fonksiyon tipini belirt
        self.emit_line(&format!("{}:", func_name));

        // Stack Frame Kurulumu (Prologue)
        // Link Register'ı (r9) ve Frame Pointer'ı (r2) kaydet
        // Stack pointer (r1) kullanılır.
        // Stack hizalaması 8 bayt, her şey 8 baytlık birimlerde (quad word).
        let frame_overhead = 16; // r2 (fp) ve r9 (lr) için
        let mut local_vars_size = func.next_local_offset * 8; // Yerel değişkenler için 8 bayt
        // Stack frame boyutu 8 veya 16 bayt hizalı olmalı.
        // Genellikle 16 bayt hizalama daha güvenlidir.
        let total_frame_size = ((local_vars_size + frame_overhead + 15) / 16) * 16;

        self.emit_line(&format!("  l.addi r1, r1, -{}", total_frame_size)); // Stack'i azalt
        self.emit_line(&format!("  l.sw r9, {}(r1)", total_frame_size - 8)); // LR'ı kaydet
        self.emit_line(&format!("  l.sw r2, {}(r1)", total_frame_size - 16)); // FP'yi kaydet
        self.emit_line("  l.ori r2, r1, 0"); // r2'yi (FP) yeni r1'e (SP) ayarla

        // Parametreleri yerel değişken ofsetlerine kopyala
        // OpenRISC ABI: Genellikle r3-r8 argümanlar için kullanılır.
        let arg_regs = ["r3", "r4", "r5", "r6", "r7", "r8"];
        for i in 0..func.parameter_count {
            if i < arg_regs.len() {
                let arg_reg = arg_regs[i];
                // Yerel değişken ofseti: FP'ye göre negatif ofset
                // r2 (FP) + (yerel değişken ofseti)
                let offset_from_fp = (i * 8) as isize; // Basitçe parametre ofseti
                self.emit_line(&format!("  l.sd {}, {}(r2)", arg_reg, offset_from_fp)); // Argümanı stack'e kaydet (store doubleword)
            } else {
                // Kalan argümanlar stack'ten alınır.
                // Bu durum daha karmaşıktır, şimdilik sadece ilk 6 argümanı destekleyelim.
                eprintln!("Uyarı: OpenRISC'te 6'dan fazla argüman şu an desteklenmiyor.");
            }
        }

        // IR Yönergelerini Çevir
        for (i, inst) in func.instructions.iter().enumerate() {
            self.emit_line(&format!(".L_{}_{}:", func_name, i)); // Etiketler

            match &inst.opcode {
                OpCode::PushInt(val) => {
                    self.emit_line(&format!("  l.movhi r3, %hi({})", val)); // Integer'ın yüksek kısmını r3'e yükle
                    self.emit_line(&format!("  l.ori r3, r3, %lo({})", val)); // Düşük kısmını birleştir
                    self.emit_line("  l.sdd r3, -8(r1)"); // r3'ü stack'e it (store doubleword, pre-decrement)
                }
                OpCode::PushBool(val) => {
                    let bool_val = if *val { 1 } else { 0 };
                    self.emit_line(&format!("  l.ori r3, r0, {}", bool_val)); // r0'dan bool_val'ı r3'e
                    self.emit_line("  l.sdd r3, -8(r1)");
                }
                OpCode::PushString(s) => {
                    if let Some(label) = self.string_literals.get(s) {
                        self.emit_line(&format!("  l.movhi r3, %hi({})", label)); // String adresinin yüksek kısmını r3'e
                        self.emit_line(&format!("  l.ori r3, r3, %lo({})", label)); // Düşük kısmını birleştir
                        self.emit_line("  l.sdd r3, -8(r1)"); // r3'ü stack'e it
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen string sabiti: {}", s)
                        )));
                    }
                }
                OpCode::LoadLocal(offset) => {
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  l.ldd r3, {}(r2)", offset_from_fp)); // Yerel değişkeni r3'e yükle
                    self.emit_line("  l.sdd r3, -8(r1)"); // r3'ü stack'e it
                }
                OpCode::StoreLocal(offset) => {
                    self.emit_line("  l.ldd r3, 0(r1)"); // Stack'ten değeri r3'e al
                    self.emit_line("  l.addi r1, r1, 8"); // Stack'ten pop et
                    let offset_from_fp = (offset * 8) as isize;
                    self.emit_line(&format!("  l.sdd r3, {}(r2)", offset_from_fp)); // r3'ü yerel değişkene kaydet
                }
                OpCode::LoadGlobal(name) => {
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  l.movhi r3, %hi({})", label));
                        self.emit_line(&format!("  l.ori r3, r3, %lo({})", label));
                        self.emit_line("  l.ldd r3, 0(r3)"); // Global değişkenin değerini r3'e yükle
                        self.emit_line("  l.sdd r3, -8(r1)");
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::StoreGlobal(name) => {
                    self.emit_line("  l.ldd r3, 0(r1)"); // Stack'ten değeri r3'e al
                    self.emit_line("  l.addi r1, r1, 8"); // Stack'ten pop et
                    if let Some(label) = self.global_variable_addresses.get(name) {
                        self.emit_line(&format!("  l.movhi r4, %hi({})", label));
                        self.emit_line(&format!("  l.ori r4, r4, %lo({})", label));
                        self.emit_line("  l.sdd r3, 0(r4)"); // r3'ü global değişkene kaydet
                    } else {
                        return Err(CompilerError::CodeGen(CodeGenError::InternalError(
                            format!("Bilinmeyen global değişken: {}", name)
                        )));
                    }
                }
                OpCode::Add => self.emit_openrisc_binary_op("l.add"),
                OpCode::Sub => self.emit_openrisc_binary_op("l.sub"),
                OpCode::Mul => self.emit_openrisc_binary_op("l.mul"),
                OpCode::Div => self.emit_openrisc_binary_op("l.div"), // İşaretli bölme
                OpCode::Eq => self.emit_openrisc_comparison_op("l.bf", "l.bnf"),
                OpCode::Ne => self.emit_openrisc_comparison_op("l.bnf", "l.bf"),
                OpCode::Lt => self.emit_openrisc_comparison_op("l.bl", "l.bge"),
                OpCode::Le => self.emit_openrisc_comparison_op("l.ble", "l.bg"),
                OpCode::Gt => self.emit_openrisc_comparison_op("l.bg", "l.ble"),
                OpCode::Ge => self.emit_openrisc_comparison_op("l.bge", "l.bl"),
                OpCode::And => self.emit_openrisc_binary_op("l.and"),
                OpCode::Or => self.emit_openrisc_binary_op("l.or"),
                OpCode::Not => {
                    self.emit_line("  l.ldd r3, 0(r1)"); // Değeri r3'e al
                    self.emit_line("  l.snez r3, r3");   // Sıfır değilse 1, sıfırsa 0 yap
                    self.emit_line("  l.xori r3, r3, 1"); // 1'i 0, 0'ı 1 yap (boolean NOT)
                    self.emit_line("  l.sdd r3, 0(r1)"); // Sonucu stack'e kaydet
                }
                OpCode::Jump(target_idx) => {
                    self.emit_line(&format!("  l.j .L_{}_{}", func_name, target_idx));
                    self.emit_line("  l.nop"); // Gecikme slotu (branch delay slot)
                }
                OpCode::JumpIfFalse(target_idx) => {
                    self.emit_line("  l.ldd r3, 0(r1)"); // Koşulu r3'e al
                    self.emit_line("  l.addi r1, r1, 8"); // Pop et
                    self.emit_line("  l.snez r3, r3"); // Sıfır değilse 1, sıfırsa 0 yap
                    self.emit_line(&format!("  l.bnf r3, .L_{}_{}", func_name, target_idx)); // Eğer 0 ise atla
                    self.emit_line("  l.nop"); // Gecikme slotu
                }
                OpCode::Call(callee_name, arg_count) => {
                    // Argümanları yığından r3-r8 kaydedicilerine yükle (sağdan sola)
                    let arg_input_regs = ["r3", "r4", "r5", "r6", "r7", "r8"];
                    for i in 0..*arg_count {
                        if i < arg_input_regs.len() {
                            let arg_reg = arg_input_regs[i];
                            let stack_offset = (*arg_count - 1 - i) * 8; // Yığından pop et
                            self.emit_line(&format!("  l.ldd {}, {}(r1)", arg_reg, stack_offset));
                        } else {
                            eprintln!("Uyarı: OpenRISC'te 6'dan fazla argüman şu an desteklenmiyor.");
                        }
                    }
                    // Argümanları stack'ten temizle
                    self.emit_line(&format!("  l.addi r1, r1, {}", arg_count * 8));

                    self.emit_line(&format!("  l.jal {}", callee_name)); // Fonksiyonu çağır (Jump and Link)
                    self.emit_line("  l.nop"); // Gecikme slotu

                    // Dönüş değeri r3'te olur, onu yığına it
                    self.emit_line("  l.sdd r3, -8(r1)");
                }
                OpCode::Return => {
                    // Dönüş değeri varsa r3'e yükle (yığının tepesinden)
                    // if func.return_type != Type::Void {
                    //     self.emit_line("  l.ldd r3, 0(r1)");
                    // }

                    // Stack Frame Yıkımı (Epilogue)
                    self.emit_line(&format!("  l.ldd r9, {}(r1)", total_frame_size - 8)); // LR'ı geri yükle
                    self.emit_line(&format!("  l.ldd r2, {}(r1)", total_frame_size - 16)); // FP'yi geri yükle
                    self.emit_line(&format!("  l.addi r1, r1, {}", total_frame_size)); // Stack'i geri al
                    self.emit_line("  l.jr r9"); // Dönüş adresine atla
                    self.emit_line("  l.nop");   // Gecikme slotu
                }
                OpCode::FunctionEnd => { /* Do nothing */ }
                OpCode::SyscallPrintInt => {
                    self.emit_openrisc_syscall_print(Type::Integer)?;
                }
                OpCode::SyscallPrintBool => {
                    self.emit_openrisc_syscall_print(Type::Boolean)?;
                }
                OpCode::SyscallPrintString => {
                    self.emit_openrisc_syscall_print(Type::String)?;
                }
                OpCode::NoOp => { /* Do nothing */ }
            }
        }
        self.emit_line(&format!(".size {}, . - {}", func_name, func_name)); // Fonksiyon boyutunu belirt
        Ok(())
    }

    /// OpenRISC için ikili operatör kodu üretir.
    fn emit_openrisc_binary_op(&mut self, instruction: &str) {
        self.emit_line("  l.ldd r4, 0(r1)"); // Sağ operandı r4'e yükle
        self.emit_line("  l.addi r1, r1, 8"); // Pop et
        self.emit_line("  l.ldd r3, 0(r1)"); // Sol operandı r3'e yükle
        self.emit_line(&format!("  {} r3, r3, r4", instruction)); // İşlemi yap (r3 = r3 op r4)
        self.emit_line("  l.sdd r3, 0(r1)"); // Sonucu stack'e kaydet
    }

    /// OpenRISC için karşılaştırma operatörü kodu üretir.
    /// `true_branch_instr`: koşul doğruysa atlama yönergesi (örn: l.bf)
    /// `false_branch_instr`: koşul yanlışsa atlama yönergesi (örn: l.bnf)
    fn emit_openrisc_comparison_op(&mut self, true_branch_instr: &str, false_branch_instr: &str) {
        self.emit_line("  l.ldd r4, 0(r1)"); // Sağ operandı r4'e
        self.emit_line("  l.addi r1, r1, 8"); // Pop et
        self.emit_line("  l.ldd r3, 0(r1)"); // Sol operandı r3'e

        self.emit_line(&format!("  l.cmp r3, r4")); // r3 ile r4'ü karşılaştır

        let true_label = String::from_format_args!(".L_true_{}", self.next_string_id);
        let end_label = String::from_format_args!(".L_end_{}", self.next_string_id);
        self.next_string_id += 1;

        self.emit_line(&format!("  {} {}", true_branch_instr, true_label)); // Koşul doğruysa true_label'a atla
        self.emit_line("  l.nop"); // Gecikme slotu

        self.emit_line("  l.ori r3, r0, 0"); // r3 = 0 (False)
        self.emit_line(&format!("  l.j {}", end_label)); // Atla
        self.emit_line("  l.nop"); // Gecikme slotu

        self.emit_line(&format!("{}:", true_label));
        self.emit_line("  l.ori r3, r0, 1"); // r3 = 1 (True)

        self.emit_line(&format!("{}:", end_label));
        self.emit_line("  l.sdd r3, 0(r1)"); // Sonucu stack'e kaydet
    }

    /// OpenRISC için sistem çağrısı ile çıktı üretir.
    /// Sahne Karnal sistem çağrılarını burada ele alıyoruz.
    fn emit_openrisc_syscall_print(&mut self, ty: Type) -> Result<()> {
        self.emit_line("  l.ldd r3, 0(r1)"); // Yığından değeri r3'e yükle (argüman 1)
        self.emit_line("  l.addi r1, r1, 8"); // Pop et

        // Linux ABI: write syscall numarası 4 (32-bit), 64 (64-bit)
        // OR1K'da genellikle write syscall numarası 4 (32-bit) olarak kullanılır.
        // Sahne64'ün 64-bit bir sistemi olduğunu varsaydığımızdan 64 numarasını kullanabiliriz.
        let syscall_num = 64; // write syscall numarası (Linux ABI)

        match self.target_config.opt_mode {
            OptimizationMode::KernelOnly => {
                // Karnal64 (Linux benzeri) syscall'ları doğrudan
                // write syscall: r3=fd (1 for stdout), r4=buf, r5=count
                self.emit_line(&format!("  l.ori r11, r0, {}", syscall_num)); // Syscall numarası r11'e (veya r0'dan r11'e)
                self.emit_line("  l.ori r3, r0, 1");                       // stdout (fd=1)
                self.emit_line("  l.ori r4, r3, 0");                       // r3'teki değeri r4'e taşı (buf - değerin kendisi)
                self.emit_line("  l.ori r5, r0, 8");                       // 8 bayt yazdır (long size, varsayımsal)
                                                                          // NOTE: Integer/Boolean için, sayıyı string'e çevirmesi gerekir
                                                                          // Bu basitleştirilmiş bir yaklaşımdır.
                self.emit_line("  l.trap 0x0"); // Sistem çağrısını tetikle
            }
            OptimizationMode::SahneAndKarnal => {
                // Sahne64 API'leri ve Karnal64 arasında seçim yapın.
                match ty {
                    Type::Integer => {
                        self.emit_line("  l.jal sahne_print_int"); // Sahne64 runtime fonksiyonu
                        self.emit_line("  l.nop");
                    }
                    Type::Boolean => {
                         self.emit_line("  l.jal sahne_print_bool");
                         self.emit_line("  l.nop");
                    }
                    Type::String => {
                        self.emit_line("  l.jal sahne_print_string");
                        self.emit_line("  l.nop");
                    }
                    _ => {
                        // Fallback to Karnal64 syscall
                        self.emit_line(&format!("  l.ori r11, r0, {}", syscall_num));
                        self.emit_line("  l.ori r3, r0, 1");
                        self.emit_line("  l.ori r4, r3, 0");
                        self.emit_line("  l.ori r5, r0, 8");
                        self.emit_line("  l.trap 0x0");
                    }
                }
            }
            _ => { // Varsayılan olarak Karnal64
                self.emit_line(&format!("  l.ori r11, r0, {}", syscall_num));
                self.emit_line("  l.ori r3, r0, 1");
                self.emit_line("  l.ori r4, r3, 0");
                self.emit_line("  l.ori r5, r0, 8");
                self.emit_line("  l.trap 0x0");
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
