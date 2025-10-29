#![no_std]

use crate::target::{TargetConfig, TargetArch, OptimizationMode};
use crate::error::{CompilerError, Result, ConfigError};
use sahne64::utils::{String, Vec, HashMap};
use sahne64::{print, println, eprintln}; // Sahne64 ortamında girdi/çıktı için

/// .sohfig yapılandırma dosyasının içeriğini temsil eder.
#[derive(Debug, Clone)]
pub struct SohfigConfig {
    pub target_arch: TargetArch,
    pub optimization_mode: OptimizationMode,
    // Gelecekte eklenebilecek diğer yapılandırma seçenekleri:
     pub output_filename: Option<String>,
     pub debug_info: bool,
}

/// .sohfig dosyasını ayrıştırmak için bir yardımcı.
pub struct SohfigParser;

impl SohfigParser {
    pub fn new() -> Self {
        SohfigParser
    }

    /// Belirtilen dosya yolundan .sohfig dosyasını okur ve ayrıştırır.
    ///
    /// Sahne Karnal ortamında doğrudan dosya okuma işlemi, işletim sisteminin
    /// sağladığı bir sistem çağrısı veya API üzerinden yapılmalıdır.
    /// Bu örnekte, dosya içeriğinin bir `String` olarak verildiğini varsayıyoruz.
    /// Gerçek bir senaryoda, bu metot `sahne64::fs::read_file(path)` gibi bir çağrı yapmalıdır.
    pub fn parse_from_string(&self, config_content: &str) -> Result<SohfigConfig> {
        let mut target_arch: Option<TargetArch> = None;
        let mut optimization_mode: Option<OptimizationMode> = None;

        for line in config_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                // Boş satırları ve yorumları atla
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(CompilerError::Config(ConfigError::InvalidFormat(
                    String::from_format_args!("Geçersiz yapılandırma satırı: {}", line)
                )));
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "target_arch" => {
                    target_arch = Some(Self::parse_target_arch(value)?);
                },
                "optimization_mode" => {
                    optimization_mode = Some(Self::parse_optimization_mode(value)?);
                },
                _ => {
                    eprintln!("Uyarı: Bilinmeyen .sohfig yapılandırma anahtarı: {}", key);
                }
            }
        }

        let final_target_arch = target_arch.ok_or_else(|| {
            CompilerError::Config(ConfigError::MissingKey("target_arch".into()))
        })?;

        let final_optimization_mode = optimization_mode.ok_or_else(|| {
            CompilerError::Config(ConfigError::MissingKey("optimization_mode".into()))
        })?;

        Ok(SohfigConfig {
            target_arch: final_target_arch,
            optimization_mode: final_optimization_mode,
        })
    }

    /// String değerden TargetArch enum'a dönüştürür.
    fn parse_target_arch(s: &str) -> Result<TargetArch> {
        match s {
            "riscv64" => Ok(TargetArch::RISCV64),
            "aarch64" => Ok(TargetArch::AArch64),
            "x86_64" => Ok(TargetArch::X86_64),
            "sparc64" => Ok(TargetArch::SPARC64),
            "openrisc" => Ok(TargetArch::OpenRISC),
            "powerpc64" => Ok(TargetArch::PowerPC64),
            "loongarch64" => Ok(TargetArch::LoongArch64),
            "mips64" => Ok(TargetArch::MIPS64),
            "elbrus" => Ok(TargetArch::Elbrus), // Elbrus için de desteği ekliyoruz
            _ => Err(CompilerError::Config(ConfigError::InvalidValue(
                String::from_format_args!("Geçersiz hedef mimarisi: {}", s)
            ))),
        }
    }

    /// String değerden OptimizationMode enum'a dönüştürür.
    fn parse_optimization_mode(s: &str) -> Result<OptimizationMode> {
        match s {
            "karnal_only" => Ok(OptimizationMode::KernelOnly),
            "sahne_and_karnal" => Ok(OptimizationMode::SahneAndKarnal),
            _ => Err(CompilerError::Config(ConfigError::InvalidValue(
                String::from_format_args!("Geçersiz optimizasyon modu: {}", s)
            ))),
        }
    }

    /// `SohfigConfig` nesnesinden bir `TargetConfig` nesnesi oluşturur.
    pub fn to_target_config(config: SohfigConfig) -> TargetConfig {
        TargetConfig::new(config.target_arch, config.optimization_mode)
    }
}
