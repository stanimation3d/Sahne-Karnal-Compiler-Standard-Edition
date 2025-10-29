// type_system.rs
#![no_std]

use sahne64::utils::String; // String için

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Integer, // i32, i64, u32, u64 gibi ayrım daha sonra yapılabilir. Şimdilik genel Integer.
    Boolean, // true, false
    String,  // "hello"
    Void,    // Fonksiyon dönüş değeri yok (unit type)
    Unknown, // Tür çıkarımı yapılamadığında veya hata durumunda kullanılır
    Error,   // Bir tür hatası tespit edildiğinde bu türü döndürebiliriz.
    // Fonksiyon türleri, diziler, struct'lar gibi daha karmaşık türler eklenebilir.
    // Function(sahne64::utils::Vec<Type>, Box<Type>), // (param_types, return_type)
}

impl Type {
    /// İki türün uyumlu olup olmadığını kontrol eder (basit eşittir kontrolü).
    /// Daha karmaşık dillerde alt türleme (subtyping) veya tür dönüştürme kuralları burada işlenir.
    pub fn is_compatible(&self, other: &Type) -> bool {
        self == other || *self == Type::Error || *other == Type::Error
        // Hata türü herhangi bir şeye uyumlu kabul edilebilir,
        // böylece hata yayılımı kolaylaşır.
    }

    /// Bir string literalini Type enum'ına dönüştürür.
    pub fn from_str(s: &str) -> Type {
        match s {
            "i32" | "i64" | "u32" | "u64" => Type::Integer, // Şimdilik hepsini Integer olarak kabul et
            "bool" => Type::Boolean,
            "string" => Type::String,
            "void" => Type::Void,
            _ => Type::Unknown, // Bilinmeyen tür adı
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Type::Integer => sahne64::utils::String::from("Integer"),
            Type::Boolean => sahne64::utils::String::from("Boolean"),
            Type::String => sahne64::utils::String::from("String"),
            Type::Void => sahne64::utils::String::from("Void"),
            Type::Unknown => sahne64::utils::String::from("Unknown"),
            Type::Error => sahne64::utils::String::from("Error"),
        }
    }
}
