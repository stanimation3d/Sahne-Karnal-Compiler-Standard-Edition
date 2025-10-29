// symbol_table.rs
#![no_std]

use sahne64::utils::HashMap;
use crate::type_system::Type; // Type enum'ına bağımlılık

#[derive(Debug, Clone, PartialEq)]
pub struct Symbol {
    pub name: sahne64::utils::String, // Sembolün adı
    pub ty: Type,                  // Sembolün türü
    pub is_mutable: bool,          // Değişken için: değiştirilebilir mi?
    pub is_initialized: bool,      // Değişken için: başlangıç değeri atanmış mı?
    // Fonksiyonlar için parametre türleri, dönüş türü gibi ek bilgiler eklenebilir.
}

/// Her bir kapsamı (scope) temsil eden bir katman.
pub struct Scope {
    symbols: HashMap<sahne64::utils::String, Symbol>,
}

impl Scope {
    pub fn new() -> Self {
        Scope {
            symbols: HashMap::new(),
        }
    }

    /// Bir sembolü mevcut kapsama ekler.
    pub fn define(&mut self, name: sahne64::utils::String, symbol: Symbol) -> Option<Symbol> {
        self.symbols.insert(name, symbol)
    }

    /// Mevcut kapsamda bir sembolü arar.
    pub fn resolve(&self, name: &str) -> Option<&Symbol> {
        self.symbols.get(name)
    }
}

/// Birden çok kapsamı (scope) yöneten sembol tablosu.
/// Kapsamlar bir stack gibi davranır (global, fonksiyon, blok).
pub struct SymbolTable {
    scopes: sahne64::utils::Vec<Scope>,
}

impl SymbolTable {
    pub fn new() -> Self {
        let mut table = SymbolTable {
            scopes: sahne64::utils::Vec::new(),
        };
        table.enter_scope(); // Global kapsamı başlat
        table
    }

    /// Yeni bir kapsam oluşturur ve stack'e ekler.
    pub fn enter_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    /// Mevcut kapsamdan çıkar ve stack'ten kaldırır.
    pub fn exit_scope(&mut self) {
        self.scopes.pop();
    }

    /// Mevcut (en içteki) kapsama bir sembol tanımlar.
    pub fn define(&mut self, name: sahne64::utils::String, symbol: Symbol) -> Option<Symbol> {
        if let Some(current_scope) = self.scopes.last_mut() {
            current_scope.define(name, symbol)
        } else {
            // Bu durum olmamalıdır, çünkü constructor'da global kapsam başlatılıyor.
            unreachable!("Sembol tablosunda hiçbir kapsam yok!");
        }
    }

    /// Bir sembolü en içten başlayarak dış kapsamlara doğru arar.
    pub fn resolve(&self, name: &str) -> Option<&Symbol> {
        // En içten başlayarak dışa doğru tüm kapsamlarda ararız.
        for scope in self.scopes.iter().rev() {
            if let Some(symbol) = scope.resolve(name) {
                return Some(symbol);
            }
        }
        None
    }

    /// Mevcut kapsamda bir sembolü arar (dış kapsamlara bakmaz).
    pub fn resolve_current_scope(&self, name: &str) -> Option<&Symbol> {
        if let Some(current_scope) = self.scopes.last() {
            current_scope.resolve(name)
        } else {
            None
        }
    }

    /// Bir sembolü en içten başlayarak dış kapsamlara doğru mutable olarak arar.
    pub fn resolve_mut(&mut self, name: &str) -> Option<&mut Symbol> {
        for scope in self.scopes.iter_mut().rev() {
            if let Some(symbol) = scope.symbols.get_mut(name) {
                return Some(symbol);
            }
        }
        None
    }
}
