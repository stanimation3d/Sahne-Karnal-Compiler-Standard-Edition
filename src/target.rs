// target.rs
#![no_std]

/// Hedef mimari enum'ı
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetArch {
    Riscv64,
    Aarch64,
    X86_64,
    Sparc64,
    Openrisc,
    Powerpc64,
    Loongarch64,
    Elbrus,
    Mips64,
    Unknown,
}

impl TargetArch {
    pub fn from_str(s: &str) -> Self {
        match s {
            "riscv64" => TargetArch::Riscv64,
            "aarch64" => TargetArch::Aarch64,
            "x86_64" => TargetArch::X86_64,
            "sparc64" => TargetArch::Sparc64,
            "openrisc" => TargetArch::Openrisc,
            "powerpc64" => TargetArch::Powerpc64,
            "loongarch64" => TargetArch::Loongarch64,
            "elbrus" => TargetArch::Elbrus,
            "mips64" => TargetArch::Mips64,
            _ => TargetArch::Unknown,
        }
    }
}

/// Hedef işletim sistemi enum'ı (şimdilik sadece Sahne Karnal)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOs {
    SahneKarnal,
    Unknown,
}

impl TargetOs {
    pub fn from_str(s: &str) -> Self {
        match s {
            "sahne_karnal" => TargetOs::SahneKarnal,
            _ => TargetOs::Unknown,
        }
    }
}

/// Optimizasyon seviyesi veya derleme modu
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimizationMode {
    KernelOnly,      // Sadece Karnal64 sistem çağrıları
    SahneAndKarnal,  // Hem Sahne64 hem de Karnal64 sistem çağrıları
    None,            // Optimizasyon yok (varsayılan)
}

impl OptimizationMode {
    pub fn from_str(s: &str) -> Self {
        match s {
            "-karnal_only" => OptimizationMode::KernelOnly,
            "-sahne_and_karnal" => OptimizationMode::SahneAndKarnal,
            _ => OptimizationMode::None,
        }
    }
}

/// Derleyicinin hedef konfigürasyonu
pub struct TargetConfig {
    pub arch: TargetArch,
    pub os: TargetOs,
    pub opt_mode: OptimizationMode,
}

impl TargetConfig {
    pub fn new(arch_str: &str, os_str: &str, opt_mode_str: &str) -> Self {
        TargetConfig {
            arch: TargetArch::from_str(arch_str),
            os: TargetOs::from_str(os_str),
            opt_mode: OptimizationMode::from_str(opt_mode_str),
        }
    }
}
