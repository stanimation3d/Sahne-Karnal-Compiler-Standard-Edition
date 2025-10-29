// assembler.rs

use crate::ir::IRModule;
use crate::target::{TargetConfig, TargetArch, OptimizationMode};
use crate::error::{CompilerError, Result, CodeGenError};
use crate::codegen_riscv64::RISCV64CodeGenerator;
use crate::codegen_aarch64::AArch64CodeGenerator;
use crate::codegen_x86_64::X86_64CodeGenerator;
use crate::codegen_sparc64::SPARC64CodeGenerator;
use crate::codegen_openrisc::OpenRISCCodeGenerator;
use crate::codegen_powerpc64::PowerPC64CodeGenerator;
use crate::codegen_loongarch64::LoongArch64CodeGenerator;
use crate::codegen_mips64::MIPS64CodeGenerator;
// Elbrus desteği için ayrı bir modül gerekli, henüz oluşturulmadı.
 use crate::codegen_elbrus::ElbrusCodeGenerator; 

use sahne64::utils::{String, Vec};
use sahne64::{print, println, eprintln}; // Karnal64'te kullanılabilecek temel çıktı fonksiyonları

/// Hedef mimariye ve optimizasyon moduna göre assembly kodu üretir.
pub struct Assembler {
    target_config: TargetConfig,
}

impl Assembler {
    pub fn new(target_config: TargetConfig) -> Self {
        Assembler {
            target_config,
        }
    }

    /// IRModule'den hedef mimariye uygun assembly kodunu üretir.
    ///
    /// Bu fonksiyon, seçilen hedef mimariye göre ilgili kod üreticiyi çağırır.
    /// Üretilen assembly kodu, daha sonra bir harici assembler (örn. GAS)
    /// ve linker tarafından işlenecektir.
    pub fn assemble_ir_module(&mut self, ir_module: &IRModule) -> Result<String> {
        println!("INFO: {} mimarisi için kod üretiliyor (Optimizasyon Modu: {:?})...",
                 self.target_config.arch.to_string(), self.target_config.opt_mode);

        let assembly_code = match self.target_config.arch {
            TargetArch::RISCV64 => {
                let mut generator = RISCV64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::AArch64 => {
                let mut generator = AArch64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::X86_64 => {
                let mut generator = X86_64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::SPARC64 => {
                let mut generator = SPARC64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::OpenRISC => {
                let mut generator = OpenRISCCodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::PowerPC64 => {
                let mut generator = PowerPC64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::LoongArch64 => {
                let mut generator = LoongArch64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            TargetArch::MIPS64 => {
                let mut generator = MIPS64CodeGenerator::new(self.target_config.clone());
                generator.generate_assembly(ir_module)?
            },
            // Elbrus desteği için ilgili kod üretici modülünü burada tanımlamanız gerekir.
            // Henüz bir `codegen_elbrus.rs` oluşturmadığımız için şimdilik NotImplemented hatası veriyoruz.
            TargetArch::Elbrus => {
                return Err(CompilerError::CodeGen(CodeGenError::NotImplemented(
                    "Elbrus mimarisi için kod üretici henüz uygulanmadı.".into()
                )));
            },
            _ => { // Diğer bilinmeyen veya desteklenmeyen mimariler için
                return Err(CompilerError::CodeGen(CodeGenError::UnsupportedTarget(
                    format!("Desteklenmeyen hedef mimari: {}", self.target_config.arch.to_string())
                )));
            }
        };

        // Optimizasyon moduna göre ek işlemler veya kontroller burada yapılabilir.
        // Örneğin, KernelOnly modunda sadece Karnal64 sistem çağrılarının kullanıldığı
        // ve Sahne64 API'lerinin çağrılmadığı doğrulanabilir (ancak bu daha çok statik analiz veya linter görevidir).
        // Şu anki kod üreticilerimiz zaten bu ayrımı yapıyor.

        Ok(assembly_code)
    }

    /// Üretilen assembly kodunu bir dosyaya yazar veya çıktı olarak verir.
    ///
    /// Gerçek bir derleyici için bu adımda genellikle bir '.s' dosyası oluşturulur.
    pub fn write_assembly_to_file(&self, filename: &str, assembly_code: &str) -> Result<()> {
        // Sahne64'te dosya sistemi erişimi için özel bir API'ye ihtiyaç duyulur.
        // Şimdilik sadece konsola yazdırma veya hata mesajı döndürme ile sınırlıyız.
        // Gerçek bir senaryoda, bu Rust kodu Karnal64 ortamında çalışırken,
        // Karnal64'ün kendi dosya yazma sistem çağrılarını kullanması gerekir.

        // Basitlik adına, şu an için kodu konsola yazdıralım.
        // Uygulamanız bir dosya sistemi arayüzü sağladığında burası güncellenebilir.
        // Örneğin: `sahne64::fs::write_file(filename, assembly_code.as_bytes())?`
        println!("\n--- Üretilen Assembly Kodu ({}) ---", filename);
        println!("{}", assembly_code);
        println!("--- Assembly Kodu Sonu ---");

        // Eğer dosya yazma başarısız olursa CompilerError::IO hatası döndürebiliriz.
        // Örnek: `Err(CompilerError::IO(format!("Dosya yazma hatası: {}", filename)))`
        Ok(())
    }
}
