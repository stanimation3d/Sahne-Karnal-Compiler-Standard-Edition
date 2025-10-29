// error.rs
#![no_std]

use crate::token::TokenKind;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LexingError {
    UnexpectedCharacter { line: usize, column: usize, character: char },
    UnterminatedString { line: usize, column: usize },
    // Diğer lexing hataları eklenebilir
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ParsingError {
    UnexpectedToken { expected: Option<TokenKind>, found: TokenKind, line: usize, column: usize },
    MissingToken { expected: TokenKind, found: TokenKind, line: usize, column: usize },
    InvalidExpression { line: usize, column: usize },
    // Diğer parsing hataları eklenebilir
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SemanticError {
    UndefinedVariable { name: String, line: usize, column: usize },
    TypeMismatch { expected: String, found: String, line: usize, column: usize },
    // Diğer semantik hataları eklenebilir
}

// Genel derleyici hata türü
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CompilerError {
    Lexing(LexingError),
    Parsing(ParsingError),
    Semantic(SemanticError),
    IoError { message: String }, // Sahne Karnal resource hataları için
    // Diğer genel hatalar (internal compiler error vb.)
}

// Result tip kısaltması
pub type Result<T> = core::result::Result<T, CompilerError>;
