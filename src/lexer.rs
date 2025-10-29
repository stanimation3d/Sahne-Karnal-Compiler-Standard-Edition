// lexer.rs
#![no_std]

use crate::token::{Token, TokenKind};
use crate::error::{LexingError, CompilerError, Result};
use sahne64::{print, println, eprintln}; // Konsol çıktıları için

pub struct Lexer<'a> {
    source: &'a str,
    chars: core::iter::Peekable<core::str::Chars<'a>>, // Karakterleri tek tek okumak için
    line: usize,
    column: usize,
    start_column: usize, // Mevcut token'ın başlangıç sütunu
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str) -> Self {
        Lexer {
            source,
            chars: source.chars().peekable(),
            line: 1,
            column: 1,
            start_column: 1,
        }
    }

    /// Kaynak kodu token'lara ayırır.
    pub fn tokenize(&mut self) -> Result<sahne64::utils::Vec<Token<'a>>> {
        let mut tokens = sahne64::utils::Vec::new();

        loop {
            self.start_column = self.column; // Yeni token'ın başlangıç sütununu işaretle

            let token = match self.advance() {
                Some(c) => match c {
                    // Tek karakterli operatörler ve ayraçlar
                    '(' => self.make_token(TokenKind::LParen),
                    ')' => self.make_token(TokenKind::RParen),
                    '{' => self.make_token(TokenKind::LBrace),
                    '}' => self.make_token(TokenKind::RBrace),
                    '[' => self.make_token(TokenKind::LBracket),
                    ']' => self.make_token(TokenKind::RBracket),
                    ',' => self.make_token(TokenKind::Comma),
                    ';' => self.make_token(TokenKind::Semicolon),
                    ':' => self.make_token(TokenKind::Colon),
                    '+' => self.make_token(TokenKind::Plus),
                    '-' => { // -> veya -
                        if self.match_char('>') {
                            self.make_token(TokenKind::Arrow)
                        } else {
                            self.make_token(TokenKind::Minus)
                        }
                    }
                    '*' => self.make_token(TokenKind::Star),
                    '/' => { // Tek satırlık yorumları atla // ...
                        if self.match_char('/') {
                            while let Some(c) = self.peek_char() {
                                if c == '\n' {
                                    break;
                                }
                                self.advance(); // Yorum karakterini atla
                            }
                            continue; // Yorum token üretmez, bir sonraki döngüye geç
                        } else {
                            self.make_token(TokenKind::Slash)
                        }
                    }
                    // İki karakterli veya tek karakterli olabilen operatörler
                    '=' => {
                        if self.match_char('=') {
                            self.make_token(TokenKind::EqEq)
                        } else {
                            self.make_token(TokenKind::Eq)
                        }
                    }
                    '!' => {
                        if self.match_char('=') {
                            self.make_token(TokenKind::BangEq)
                        } else {
                            self.make_token(TokenKind::Bang)
                        }
                    }
                    '<' => {
                        if self.match_char('=') {
                            self.make_token(TokenKind::LtEq)
                        } else {
                            self.make_token(TokenKind::Lt)
                        }
                    }
                    '>' => {
                        if self.match_char('=') {
                            self.make_token(TokenKind::GtEq)
                        } else {
                            self.make_token(TokenKind::Gt)
                        }
                    }
                    '&' => {
                        if self.match_char('&') {
                            self.make_token(TokenKind::And)
                        } else {
                            // Hata: Tek '&' karakterine izin verilmiyor
                            return Err(CompilerError::Lexing(LexingError::UnexpectedCharacter {
                                line: self.line,
                                column: self.start_column,
                                character: '&',
                            }));
                        }
                    }
                    '|' => {
                        if self.match_char('|') {
                            self.make_token(TokenKind::Or)
                        } else {
                            // Hata: Tek '|' karakterine izin verilmiyor
                            return Err(CompilerError::Lexing(LexingError::UnexpectedCharacter {
                                line: self.line,
                                column: self.start_column,
                                character: '|',
                            }));
                        }
                    }
                    '.' => self.make_token(TokenKind::Dot), // Yeni: Dot operatörü için

                    // String Literaller
                    '"' => self.string()?,

                    // Whitespace (boşluk karakterlerini atla)
                    c if c.is_ascii_whitespace() => {
                        if c == '\n' {
                            self.line += 1;
                            self.column = 1; // Yeni satırda sütunu sıfırla
                        }
                        continue; // Boşluk token üretmez, bir sonraki döngüye geç
                    }

                    // Rakamlar (Integer Literaller)
                    c if c.is_ascii_digit() => self.number()?,

                    // Harfler ve Alt Çizgi (Identifier veya Anahtar Kelime)
                    c if c.is_ascii_alphabetic() || c == '_' => self.identifier_or_keyword(),

                    // Bilinmeyen karakter
                    c => {
                        return Err(CompilerError::Lexing(LexingError::UnexpectedCharacter {
                            line: self.line,
                            column: self.start_column,
                            character: c,
                        }));
                    }
                },
                None => { // Dosya Sonu
                    self.start_column = self.column; // EOF token'ın sütununu da ayarla
                    self.make_token(TokenKind::Eof)
                },
            };

            // Eğer Eof token'ı üretildiyse, döngüyü sonlandır
            if token.kind == TokenKind::Eof {
                tokens.push(token);
                break;
            }

            // Normal bir token ise listeye ekle
            tokens.push(token);
        }

        Ok(tokens)
    }

    /// Sonraki karakteri ilerletir ve döndürür, konum bilgilerini günceller.
    fn advance(&mut self) -> Option<char> {
        let current_char = self.chars.next();
        if current_char.is_some() {
            self.column += 1;
        }
        current_char
    }

    /// Sonraki karaktere göz atar (ilerletmeden).
    fn peek_char(&mut self) -> Option<&char> {
        self.chars.peek()
    }

    /// Sonraki karakterin beklenen karakterle eşleşip eşleşmediğini kontrol eder.
    /// Eşleşiyorsa, karakteri tüketir (ilerletir) ve `true` döner, aksi halde `false`.
    fn match_char(&mut self, expected: char) -> bool {
        if let Some(&c) = self.peek_char() {
            if c == expected {
                self.advance(); // Karakteri tüket
                return true;
            }
        }
        false
    }

    /// Mevcut token'ın metin değerini ve konum bilgilerini alır.
    fn get_lexeme(&self) -> &'a str {
        let start_byte_idx = self.source.char_indices().nth(self.column - self.start_column).map(|(idx, _)| idx).unwrap_or(0);
        let end_byte_idx = self.source.char_indices().nth(self.column - 1).map(|(idx, _)| idx + 1).unwrap_or(self.source.len());

        // Daha doğru bir lexeme çıkarma için, karakterlerin UTF-8 byte offsetlerini takip etmek gerekir.
        // Şimdilik basitleştirilmiş bir yaklaşım kullanıyoruz.
        // Daha robust bir implementasyon için `start_offset` ve `current_offset` tutulmalıdır.

        // Geçici çözüm: `source.char_indices()` ile indeks aralığını bulmak
        let current_char_idx = self.source.char_indices().nth(self.column - 1).unwrap().0;
        let start_char_idx = self.source.char_indices().nth(self.start_column - 1).unwrap().0;

        &self.source[start_char_idx..current_char_idx]
    }

    /// Verilen türde yeni bir Token oluşturur. Lexeme'i otomatik olarak çıkarır.
    fn make_token(&self, kind: TokenKind) -> Token<'a> {
        // Bu fonksiyonun çağrıldığı anda `self.column` zaten token'ın sonuna işaret etmeli.
        // `self.start_column` ise token'ın başlangıcını işaret etmeli.
        let end_byte_offset = self.source.char_indices().nth(self.column - 1).map(|(idx, _)| idx + 1).unwrap_or(self.source.len());
        let start_byte_offset = self.source.char_indices().nth(self.start_column - 1).map(|(idx, _)| idx).unwrap_or(0);

        let lexeme = &self.source[start_byte_offset..end_byte_offset];
        Token::new(kind, lexeme, self.line, self.column - lexeme.chars().count()) // Sütun düzeltmesi
    }

    /// Tam sayı literalini ayrıştırır.
    fn number(&mut self) -> Result<Token<'a>> {
        // Rakamları tüket
        while let Some(&c) = self.peek_char() {
            if c.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }
        // Şimdilik sadece tam sayıları destekliyoruz. Ondalıklı sayılar (float) eklenebilir.
        Ok(self.make_token(TokenKind::Integer))
    }

    /// String literalini ayrıştırır (açılış tırnağı zaten tüketilmiş olmalı).
    fn string(&mut self) -> Result<Token<'a>> {
        // Kapanış tırnağına veya dosya sonuna kadar ilerle
        while let Some(&c) = self.peek_char() {
            if c == '"' {
                break;
            }
            if c == '\n' { // Çok satırlı stringlere izin vermiyorsak hata
                return Err(CompilerError::Lexing(LexingError::UnterminatedString {
                    line: self.line,
                    column: self.start_column,
                }));
            }
            self.advance();
        }

        if self.peek_char().is_none() {
            // Dosya sonuna ulaşıldı ve string kapanmadı
            return Err(CompilerError::Lexing(LexingError::UnterminatedString {
                line: self.line,
                column: self.start_column,
            }));
        }

        self.advance(); // Kapanış tırnağını tüket
        Ok(self.make_token(TokenKind::String))
    }

    /// Identifier veya anahtar kelimeyi ayrıştırır.
    fn identifier_or_keyword(&mut self) -> Token<'a> {
        // Harf, rakam veya alt çizgi olduğu sürece ilerle
        while let Some(&c) = self.peek_char() {
            if c.is_ascii_alphanumeric() || c == '_' {
                self.advance();
            } else {
                break;
            }
        }

        // Lexeme'i al ve anahtar kelime tablosuna bak
        let current_lexeme_end_idx = self.source.char_indices().nth(self.column - 1).unwrap().0;
        let current_lexeme_start_idx = self.source.char_indices().nth(self.start_column - 1).unwrap().0;
        let lexeme_slice = &self.source[current_lexeme_start_idx..current_lexeme_end_idx];

        // Anahtar kelimeleri kontrol et
        let kind = match lexeme_slice {
            "fn" => TokenKind::Fn,
            "let" => TokenKind::Let,
            "mut" => TokenKind::Mut,
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "while" => TokenKind::While,
            "return" => TokenKind::Return,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            _ => TokenKind::Identifier, // Anahtar kelime değilse identifier
        };

        self.make_token(kind)
    }
}
