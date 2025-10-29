#![no_std]

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TokenKind {
    // Anahtar Kelimeler
    Fn,      // fn
    Let,     // let
    Mut,     // mut
    If,      // if
    Else,    // else
    While,   // while
    Return,  // return
    True,    // true
    False,   // false

    // Operatörler
    Plus,    // +
    Minus,   // -
    Star,    // *
    Slash,   // /
    Eq,      // =
    EqEq,    // ==
    BangEq,  // !=
    Lt,      // <
    LtEq,    // <=
    Gt,      // >
    GtEq,    // >=
    And,     // &&
    Or,      // ||
    Bang,    // !

    // Ayraçlar ve Noktalama İşaretleri
    LParen,  // (
    RParen,  // )
    LBrace,  // {
    RBrace,  // }
    LBracket,// [
    RBracket,// ]
    Comma,   // ,
    Semicolon, // ;
    Colon,   // :
    Arrow,   // -> (fonksiyon dönüş tipi için)
    Dot,     // .

    // Literaller
    Identifier, // Değişken, fonksiyon adı vb.
    Integer,    // Tam sayı (örn. 123)
    String,     // Metin dizisi (örn. "hello")

    // Özel Tokenlar
    Eof,     // End of File (Dosya Sonu)
    Unknown, // Bilinmeyen karakter veya geçersiz token
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<'a> {
    pub kind: TokenKind,
    pub lexeme: &'a str, // Kaynak kodundaki token'ın metin değeri
    pub line: usize,
    pub column: usize,
}

impl<'a> Token<'a> {
    pub fn new(kind: TokenKind, lexeme: &'a str, line: usize, column: usize) -> Self {
        Token { kind, lexeme, line, column }
    }
}
