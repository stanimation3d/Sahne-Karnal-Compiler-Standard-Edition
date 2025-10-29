// parser.rs
#![no_std]

use crate::token::{Token, TokenKind};
use crate::ast::{Program, FunctionDeclaration, Statement, Expression};
use crate::error::{ParsingError, CompilerError, Result};
use sahne64::{print, println, eprintln}; // Konsol çıktıları için

pub struct Parser<'a> {
    tokens: sahne64::utils::Vec<Token<'a>>,
    current: usize, // Mevcut token'ın indeksi
}

impl<'a> Parser<'a> {
    pub fn new(tokens: sahne64::utils::Vec<Token<'a>>) -> Self {
        Parser { tokens, current: 0 }
    }

    /// Derleme birimini (programı) ayrıştırır.
    pub fn parse(&mut self) -> Result<Program<'a>> {
        let mut functions = sahne64::utils::Vec::new();
        let mut statements = sahne64::utils::Vec::new();

        // Fonksiyon bildirimleri ve global bildirimler
        while !self.is_at_end() {
            if self.peek().kind == TokenKind::Fn {
                functions.push(self.function_declaration()?);
            } else {
                statements.push(self.declaration()?);
            }
        }

        Ok(Program { functions, statements })
    }

    // --- Yardımcı Metotlar ---

    /// Mevcut token'a göz atar.
    fn peek(&self) -> &Token<'a> {
        &self.tokens[self.current]
    }

    /// Bir sonraki token'a göz atar (peek() ile aynı token'a).
    fn previous(&self) -> &Token<'a> {
        &self.tokens[self.current - 1]
    }

    /// Token akışında sonda mıyız?
    fn is_at_end(&self) -> bool {
        self.peek().kind == TokenKind::Eof
    }

    /// Token'ı tüketir ve bir sonraki token'a geçer.
    fn advance(&mut self) -> &Token<'a> {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }

    /// Mevcut token'ın verilen türlerden biriyle eşleşip eşleşmediğini kontrol eder.
    /// Eşleşiyorsa, token'ı tüketir (ilerletir) ve true döndürür.
    fn matches(&mut self, kinds: &[TokenKind]) -> bool {
        for &kind in kinds {
            if self.check(kind) {
                self.advance();
                return true;
            }
        }
        false
    }

    /// Mevcut token'ın verilen türde olup olmadığını kontrol eder (ilerletmez).
    fn check(&self, kind: TokenKind) -> bool {
        if self.is_at_end() {
            return false;
        }
        self.peek().kind == kind
    }

    /// Mevcut token'ın beklenen türde olduğunu varsayar ve tüketir.
    /// Eğer beklenen türde değilse hata fırlatır.
    fn consume(&mut self, kind: TokenKind, message: &'static str) -> Result<&Token<'a>> {
        if self.check(kind) {
            Ok(self.advance())
        } else {
            let found_token = self.peek().clone(); // Hata raporlama için kopyala
            Err(CompilerError::Parsing(ParsingError::UnexpectedToken {
                expected: Some(kind),
                found: found_token.kind,
                line: found_token.line,
                column: found_token.column,
            }))
        }
    }

    /// Hata durumunda parser'ı senkronize etmeye çalışır.
    /// Böylece tek bir hata tüm derleme sürecini durdurmaz.
    fn synchronize(&mut self) {
        self.advance(); // Hatalı token'ı atla

        while !self.is_at_end() {
            if self.previous().kind == TokenKind::Semicolon { // Noktalı virgülden sonra senkronize olabiliriz
                return;
            }

            match self.peek().kind {
                TokenKind::Fn | TokenKind::Let | TokenKind::If | TokenKind::While | TokenKind::Return => {
                    return; // Yeni bir bildirim başlangıcına ulaşıldı
                }
                _ => {}
            }
            self.advance();
        }
    }

    // --- Gramer Kuralları (Recursive Descent) ---

    // Top-level bildirimler: Fonksiyonlar veya diğer global bildirimler
    fn declaration(&mut self) -> Result<Statement<'a>> {
        let res = if self.matches(&[TokenKind::Let]) {
            self.var_declaration()
        } else {
            self.statement()
        };

        if res.is_err() {
            self.synchronize(); // Hata durumunda senkronize ol
        }
        res
    }

    // Değişken bildirimi: `let` ifadesi
    // let name [: Type] [= initializer];
    fn var_declaration(&mut self) -> Result<Statement<'a>> {
        let name_token = self.consume(TokenKind::Identifier, "Değişken adı bekleniyor.")?.clone();
        
        let mut mutable = false;
        if name_token.lexeme == "mut" { // Eğer "mut" kelimesi identifier olarak okunmuşsa
            // Bu kısım aslında lexer'da 'mut' bir keyword olarak ayrıştırıldığı için
            // buradaki name_token asla "mut" olmayacak.
            // Bu kontrol, dilin eğer 'mut' kelimesini identifier olarak kabul etme esnekliği
            // olsaydı geçerli olurdu. Mevcut TokenKind::Mut ile, mutability farklı ele alınacak.
            // Yani, let mut x = 10; -> let Token, mut Token, x Token, = Token, 10 Token
            // Bu durumda, name_token "x" olacak. 'mut' anahtar kelimesini 'let'ten sonra arayalım.
            // Düzeltme: Eğer `let`ten sonra `mut` geliyorsa, onu tüketelim.
            // self.previous() 'let' olacak, sonra 'mut'u kontrol edelim.
        }

        // 'let' token'ından sonra 'mut' keyword'ünü arayalım
        if self.check(TokenKind::Mut) {
            self.advance(); // `mut` keyword'ünü tüket
            mutable = true;
            // Değişken adını tekrar tüketmemiz gerekebilir, çünkü `mut` arasına girmiş oldu.
            // Bu, dil tasarımına bağlı. Rust'ta `let mut x` yapısı var.
            // Bizim lexer'ımız `mut`'u bir `TokenKind::Mut` olarak tanıyor.
            // Bu durumda, `let`ten sonra `mut` gelirse, `name_token` aslında `mut` değil,
            // `mut`'tan sonra gelen identifier olmalı.

            // Yeniden düzenleme: let'ten sonra `mut` var mı kontrol et, varsa consume et.
            // Ardından identifier'ı tüket.
            let actual_name_token = self.consume(TokenKind::Identifier, "Değişken adı bekleniyor.")?.clone();
            // name_token'ı güncelleyelim.
            let name_token = actual_name_token;
        }


        let mut type_annotation = None;
        if self.matches(&[TokenKind::Colon]) { // Tür bildirimi: : i32
            type_annotation = Some(self.consume(TokenKind::Identifier, "Tür adı bekleniyor.")?.clone());
        }

        let mut initializer = None;
        if self.matches(&[TokenKind::Eq]) { // Başlangıç değeri: = 10
            initializer = Some(self.expression()?);
        }

        self.consume(TokenKind::Semicolon, "Değişken bildiriminden sonra ';' bekleniyor.")?;
        Ok(Statement::VarDeclaration {
            name: name_token,
            initializer,
            mutable,
            type_annotation,
        })
    }


    // Fonksiyon bildirimi: `fn` ifadesi
    // fn name (parameters) [: return_type] { body }
    fn function_declaration(&mut self) -> Result<FunctionDeclaration<'a>> {
        self.consume(TokenKind::Fn, "Fonksiyon bildirimi 'fn' ile başlamalı.")?;
        let name = self.consume(TokenKind::Identifier, "Fonksiyon adı bekleniyor.")?.clone();

        self.consume(TokenKind::LParen, "Fonksiyon adından sonra '(' bekleniyor.")?;
        let mut parameters = sahne64::utils::Vec::new();
        if !self.check(TokenKind::RParen) { // Parametreler var mı?
            loop {
                if parameters.len() >= 255 { // Maksimum parametre sınırı (örnek)
                    return Err(CompilerError::Parsing(ParsingError::InvalidExpression {
                        line: self.peek().line,
                        column: self.peek().column,
                    }));
                }
                parameters.push(self.consume(TokenKind::Identifier, "Parametre adı bekleniyor.")?.clone());
                if !self.matches(&[TokenKind::Comma]) {
                    break;
                }
            }
        }
        self.consume(TokenKind::RParen, "Fonksiyon parametrelerinden sonra ')' bekleniyor.")?;

        let mut return_type = None;
        if self.matches(&[TokenKind::Arrow]) { // -> ile dönüş türü
            return_type = Some(self.consume(TokenKind::Identifier, "Dönüş türü bekleniyor.")?.clone());
        }

        self.consume(TokenKind::LBrace, "Fonksiyon gövdesi '{' ile başlamalı.")?;
        let body = self.block_statement()?;

        Ok(FunctionDeclaration { name, parameters, return_type, body })
    }


    // Blok ifadesi: `{ ... }`
    fn block_statement(&mut self) -> Result<Statement<'a>> {
        let mut statements = sahne64::utils::Vec::new();

        while !self.check(TokenKind::RBrace) && !self.is_at_end() {
            statements.push(self.declaration()?);
        }

        self.consume(TokenKind::RBrace, "Bloğun sonunda '}' bekleniyor.")?;
        Ok(Statement::Block(statements))
    }

    // Diğer bildirim türleri
    fn statement(&mut self) -> Result<Statement<'a>> {
        if self.matches(&[TokenKind::If]) {
            return self.if_statement();
        }
        if self.matches(&[TokenKind::While]) {
            return self.while_statement();
        }
        if self.matches(&[TokenKind::Return]) {
            return self.return_statement();
        }
        // Şimdilik sadece ifade bildirimini (expression statement) veya print'i ele alalım.
        self.expression_statement()
    }

    // `if` ifadesi
    fn if_statement(&mut self) -> Result<Statement<'a>> {
        self.consume(TokenKind::LParen, "'if' ifadesinden sonra '(' bekleniyor.")?;
        let condition = self.expression()?;
        self.consume(TokenKind::RParen, "'if' koşulundan sonra ')' bekleniyor.")?;

        let then_branch = Box::new(self.statement()?); // `if` gövdesi bir statement olabilir
        let mut else_branch = None;
        if self.matches(&[TokenKind::Else]) {
            else_branch = Some(Box::new(self.statement()?));
        }

        Ok(Statement::If { condition, then_branch, else_branch })
    }

    // `while` döngüsü
    fn while_statement(&mut self) -> Result<Statement<'a>> {
        self.consume(TokenKind::LParen, "'while' ifadesinden sonra '(' bekleniyor.")?;
        let condition = self.expression()?;
        self.consume(TokenKind::RParen, "'while' koşulundan sonra ')' bekleniyor.")?;

        let body = Box::new(self.statement()?);
        Ok(Statement::While { condition, body })
    }

    // `return` ifadesi
    fn return_statement(&mut self) -> Result<Statement<'a>> {
        let keyword = self.previous().clone(); // `return` token'ını al
        let mut value = None;

        // Eğer bir sonraki token ';' değilse, dönüş değeri var demektir.
        if !self.check(TokenKind::Semicolon) {
            value = Some(self.expression()?);
        }

        self.consume(TokenKind::Semicolon, "Dönüş ifadesinden sonra ';' bekleniyor.")?;
        Ok(Statement::Return { keyword, value })
    }

    // İfade bildirimi: `expression;`
    fn expression_statement(&mut self) -> Result<Statement<'a>> {
        let expr = self.expression()?;
        self.consume(TokenKind::Semicolon, "İfadeden sonra ';' bekleniyor.")?;
        Ok(Statement::Expression(expr))
    }

    // --- İfade Ayrıştırma (Operatör Önceliği) ---

    // En düşük öncelik: Atama
    fn expression(&mut self) -> Result<Expression<'a>> {
        self.assignment()
    }

    // Atama (sağdan sola)
    fn assignment(&mut self) -> Result<Expression<'a>> {
        let expr = self.or()?; // 'or' operatöründen daha yüksek önceliği olan bir ifade ayrıştır

        // Eğer 'eşit' token'ı varsa, bu bir atamadır.
        if self.matches(&[TokenKind::Eq]) {
            let equals = self.previous().clone(); // '=' token'ını al
            let value = self.assignment()?; // Sağ tarafı tekrar atama olarak ayrıştır (sağdan sola)

            if let Expression::Identifier(name) = expr {
                return Ok(Expression::Assign { name, value: Box::new(value) });
            } else {
                // Atamanın sol tarafı geçerli bir atama hedefi değilse hata
                return Err(CompilerError::Parsing(ParsingError::InvalidExpression {
                    line: equals.line,
                    column: equals.column,
                }));
            }
        }
        Ok(expr)
    }

    // Mantıksal OR
    fn or(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.and()?;
        while self.matches(&[TokenKind::Or]) {
            let operator = self.previous().clone();
            let right = self.and()?;
            expr = Expression::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    // Mantıksal AND
    fn and(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.equality()?;
        while self.matches(&[TokenKind::And]) {
            let operator = self.previous().clone();
            let right = self.equality()?;
            expr = Expression::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    // Eşitlik ve Eşitsizlik
    fn equality(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.comparison()?;
        while self.matches(&[TokenKind::BangEq, TokenKind::EqEq]) {
            let operator = self.previous().clone();
            let right = self.comparison()?;
            expr = Expression::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    // Karşılaştırma operatörleri
    fn comparison(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.term()?;
        while self.matches(&[TokenKind::Gt, TokenKind::GtEq, TokenKind::Lt, TokenKind::LtEq]) {
            let operator = self.previous().clone();
            let right = self.term()?;
            expr = Expression::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    // Toplama ve Çıkarma
    fn term(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.factor()?;
        while self.matches(&[TokenKind::Minus, TokenKind::Plus]) {
            let operator = self.previous().clone();
            let right = self.factor()?;
            expr = Expression::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    // Çarpma ve Bölme
    fn factor(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.unary()?;
        while self.matches(&[TokenKind::Slash, TokenKind::Star]) {
            let operator = self.previous().clone();
            let right = self.unary()?;
            expr = Expression::Binary {
                left: Box::new(expr),
                operator,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    // Tekli operatörler (Unary)
    fn unary(&mut self) -> Result<Expression<'a>> {
        if self.matches(&[TokenKind::Bang, TokenKind::Minus]) {
            let operator = self.previous().clone();
            let right = self.unary()?; // Sağdan sola bağlama
            return Ok(Expression::Unary {
                operator,
                right: Box::new(right),
            });
        }
        self.call() // Tekli operatörden sonra çağrıya veya birincil ifadeye geç
    }

    // Fonksiyon çağrısı ve nokta operatörü (şimdilik sadece çağrı)
    fn call(&mut self) -> Result<Expression<'a>> {
        let mut expr = self.primary()?;

        loop {
            if self.matches(&[TokenKind::LParen]) { // Fonksiyon çağrısı
                expr = self.finish_call(expr)?;
            } else if self.matches(&[TokenKind::Dot]) { // Nokta operatörü (örn. object.field)
                // Şimdilik sadece çağrıları destekliyoruz, nokta operatörü için AST'ye
                // yeni bir Expression::FieldAccess veya benzeri bir tür eklenmelidir.
                // Örneğin:
                 let field_name = self.consume(TokenKind::Identifier, "Alan adı bekleniyor.")?.clone();
                 expr = Expression::FieldAccess { object: Box::new(expr), field: field_name };
                return Err(CompilerError::Parsing(ParsingError::InvalidExpression {
                    line: self.previous().line,
                    column: self.previous().column,
                }));
            }
            else {
                break;
            }
        }
        Ok(expr)
    }

    // Fonksiyon çağrısını tamamlar
    fn finish_call(&mut self, callee: Expression<'a>) -> Result<Expression<'a>> {
        let mut arguments = sahne64::utils::Vec::new();
        if !self.check(TokenKind::RParen) { // Argümanlar var mı?
            loop {
                if arguments.len() >= 255 { // Maksimum argüman sınırı (örnek)
                    return Err(CompilerError::Parsing(ParsingError::InvalidExpression {
                        line: self.peek().line,
                        column: self.peek().column,
                    }));
                }
                arguments.push(self.expression()?);
                if !self.matches(&[TokenKind::Comma]) {
                    break;
                }
            }
        }
        let paren = self.consume(TokenKind::RParen, "Argümanlardan sonra ')' bekleniyor.")?.clone();
        Ok(Expression::Call {
            callee: Box::new(callee),
            paren,
            arguments,
        })
    }

    // En yüksek öncelik: Literaller, Identifier'lar, Parantezli İfadeler
    fn primary(&mut self) -> Result<Expression<'a>> {
        if self.matches(&[TokenKind::False]) {
            return Ok(Expression::Literal(self.previous().clone()));
        }
        if self.matches(&[TokenKind::True]) {
            return Ok(Expression::Literal(self.previous().clone()));
        }
        if self.matches(&[TokenKind::Integer, TokenKind::String]) {
            return Ok(Expression::Literal(self.previous().clone()));
        }
        if self.matches(&[TokenKind::Identifier]) {
            return Ok(Expression::Identifier(self.previous().clone()));
        }

        if self.matches(&[TokenKind::LParen]) {
            let expr = self.expression()?;
            self.consume(TokenKind::RParen, "İfadeyi takiben ')' bekleniyor.")?;
            return Ok(Expression::Grouping { expression: Box::new(expr) });
        }

        // Bilinmeyen veya beklenmedik bir token
        let found_token = self.peek().clone();
        Err(CompilerError::Parsing(ParsingError::UnexpectedToken {
            expected: None, // Belirli bir beklenti yok
            found: found_token.kind,
            line: found_token.line,
            column: found_token.column,
        }))
    }
}
