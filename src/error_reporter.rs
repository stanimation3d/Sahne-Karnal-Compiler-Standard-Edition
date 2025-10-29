// error_reporter.rs
#![no_std]

use crate::error::{LexingError, ParsingError, SemanticError};
use crate::token::Token; // Token'ı kullanmak için

// Basit bir konsol çıktısı kullanarak hata raporlama
// Gerçek bir uygulamada, bu renkli çıktılar veya daha detaylı bilgiler içerebilir.

pub fn report_lexing_error(error: &LexingError, _source_code: &str) {
    match error {
        LexingError::UnexpectedCharacter { line, column, character } => {
            eprintln!("[Lexing Hata] Satır {}:{} - Beklenmedik karakter '{}'", line, column, character);
        }
        LexingError::UnterminatedString { line, column } => {
            eprintln!("[Lexing Hata] Satır {}:{} - Tamamlanmamış string literal", line, column);
        }
    }
    // Kaynak kodda ilgili satırı gösterme gibi geliştirmeler yapılabilir.
}

pub fn report_parsing_error(error: &ParsingError, _source_code: &str) {
    match error {
        ParsingError::UnexpectedToken { expected, found, line, column } => {
            eprintln!("[Parsing Hata] Satır {}:{} - Beklenmedik token: {:?}. Beklenen: {:?}", line, column, found, expected);
        }
        ParsingError::MissingToken { expected, found, line, column } => {
            eprintln!("[Parsing Hata] Satır {}:{} - Eksik token: {:?}. Bulunan: {:?}", line, column, expected, found);
        }
        ParsingError::InvalidExpression { line, column } => {
            eprintln!("[Parsing Hata] Satır {}:{} - Geçersiz ifade", line, column);
        }
    }
}

pub fn report_semantic_error(error: &SemanticError, _source_code: &str) {
    match error {
        SemanticError::UndefinedVariable { name, line, column } => {
            eprintln!("[Semantik Hata] Satır {}:{} - Tanımlanmamış değişken: '{}'", line, column, name);
        }
        SemanticError::TypeMismatch { expected, found, line, column } => {
            eprintln!("[Semantik Hata] Satır {}:{} - Tür uyumsuzluğu. Beklenen: {}, Bulunan: {}", line, column, expected, found);
        }
    }
}
