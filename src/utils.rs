// utils.rs
#![no_std]

// sahne64 çekirdek kütüphanesinden temel veri yapılarını ve I/O fonksiyonlarını içeri aktar
// Bu, derleyicimizin no_std ortamında çalışmasını sağlar.
use sahne64::utils::{String, Vec, HashMap, fmt}; // fmt modülü format! macro'su için gereklidir
use sahne64::{print, println, eprintln}; // Sahne64'ün kendi temel çıktı fonksiyonları

// --- Hata İşleme Yardımcıları ---
// CompilerError içindeki hatalar için formatlama yardımcıları (şimdilik doğrudan buraya entegre)

// --- Debug ve Geliştirme Yardımcıları ---

/// Bir değeri konsola hata ayıklama amaçlı yazdırmak için yardımcı makro.
/// Sadece debug modunda veya belirli bir flag ile aktif hale getirilebilir.
/// Şimdilik her zaman yazdırır.
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {{
        // Karnal64'te direkt println kullanılabilir.
        // Gelecekte, debug_info flag'ine bağlı olarak derleme sırasında kapatılabilir.
        $crate::println!($($arg)*);
    }};
}

/// Bir değeri konsola hata ayıklama amaçlı yazdırmak için yardımcı makro (eprintln versiyonu).
#[macro_export]
macro_rules! debug_eprintln {
    ($($arg:tt)*) => {{
        $crate::eprintln!($($arg)*);
    }};
}

// --- Metin İşleme Yardımcıları ---

/// String'i küçük harfe dönüştürür.
/// Not: `no_std` ortamında Unicode desteği kısıtlı olabilir. Sadece ASCII için güvenlidir.
pub fn to_lowercase(s: &String) -> String {
    let mut new_s = String::new();
    for c in s.chars() {
        // Rust'ın no_std String'i char iteratörü sağlıyorsa kullanılabilir.
        // Aksi takdirde, byte bazında elle dönüşüm yapılmalıdır.
        if c >= 'A' && c <= 'Z' {
            new_s.push((c as u8 + 32) as char); // ASCII için A-Z'yi a-z'ye çevir
        } else {
            new_s.push(c);
        }
    }
    new_s
}

/// String'i büyük harfe dönüştürür.
/// Not: `no_std` ortamında Unicode desteği kısıtlı olabilir. Sadece ASCII için güvenlidir.
pub fn to_uppercase(s: &String) -> String {
    let mut new_s = String::new();
    for c in s.chars() {
        if c >= 'a' && c <= 'z' {
            new_s.push((c as u8 - 32) as char); // ASCII için a-z'yi A-Z'ye çevir
        } else {
            new_s.push(c);
        }
    }
    new_s
}

// --- Bellek Yönetimi Yardımcıları (Opsiyonel, eğer özel bir allocator kullanılıyorsa) ---
// Sahne64 zaten kendi bellek yönetimi (String, Vec, HashMap için) sağlıyorsa buraya ek bir şey gerekmez.

// --- Diğer Genel Yardımcılar ---

/// Sayısal değerleri string'e dönüştürmek için basit bir yardımcı.
/// `no_std` ortamında `itoa` veya benzeri crate'ler kullanılabilir.
/// Sahne64'ün `String::from_format_args!` makrosu bu işlevi görebilir.
pub fn int_to_string(n: i64) -> String {
    String::from_format_args!("{}", n)
}

/// Boolean değerleri string'e dönüştürmek için basit bir yardımcı.
pub fn bool_to_string(b: bool) -> String {
    if b {
        String::from_str("true")
    } else {
        String::from_str("false")
    }
}

// Gelecekte eklenebilecek yardımcı fonksiyonlar:
// - Basit dosya işlemleri (Sahne64 API'leri ile entegre)
// - Hashing fonksiyonları (HashMap için zaten sahne64'ün sağladığı kullanılır)
// - Çeşitli veri yapısı uzantıları (örn. bir String üzerinde regex benzeri işlemler)
