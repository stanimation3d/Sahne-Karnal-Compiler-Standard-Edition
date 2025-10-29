// ast.rs
#![no_std]

use crate::token::{Token, TokenKind}; // AST düğümlerinde token konum bilgisi için

// Temel AST Düğüm Türleri
#[derive(Debug, PartialEq, Clone)]
pub enum Expression<'a> {
    Literal(Token<'a>), // Sayı, string, true/false
    Identifier(Token<'a>), // Değişken adı
    Binary { // İkili operatörler: a + b, x == y
        left: Box<Expression<'a>>,
        operator: Token<'a>,
        right: Box<Expression<'a>>,
    },
    Unary { // Tekli operatörler: -x, !b
        operator: Token<'a>,
        right: Box<Expression<'a>>,
    },
    Call { // Fonksiyon çağrısı: func(arg1, arg2)
        callee: Box<Expression<'a>>, // Genellikle Identifier olur
        paren: Token<'a>, // '(' token'ı (konum bilgisi için)
        arguments: sahne64::utils::Vec<Expression<'a>>,
    },
    Grouping { // Parantezli ifadeler: (a + b)
        expression: Box<Expression<'a>>,
    },
    // Diğer ifade türleri eklenebilir: Diziler, Struct alan erişimleri vb.
    Assign { // Atama ifadesi: x = 10
        name: Token<'a>, // Hedef değişken (Identifier)
        value: Box<Expression<'a>>,
    },
     Literal {
        token: Token<'a>,
        ty: Type, // Eklendi
    },
    Identifier {
        token: Token<'a>,
        ty: Type, // Eklendi
    },
    Binary {
        left: Box<Expression<'a>>,
        operator: Token<'a>,
        right: Box<Expression<'a>>,
        ty: Type, // Eklendi
    },
    Unary {
        operator: Token<'a>,
        right: Box<Expression<'a>>,
        ty: Type, // Eklendi
    },
    Call {
        callee: Box<Expression<'a>>,
        paren: Token<'a>,
        arguments: sahne64::utils::Vec<Expression<'a>>,
        ty: Type, // Eklendi (fonksiyonun dönüş türü)
    },
    Grouping {
        expression: Box<Expression<'a>>,
        ty: Type, // Eklendi
    },
    Assign {
        name: Token<'a>,
        value: Box<Expression<'a>>,
        ty: Type, // Eklendi (atanan değerin türü)
    },
}

#[derive(Debug, PartialEq, Clone)]
pub enum Statement<'a> {
    Expression(Expression<'a>), // Sadece ifade içeren satır (örn. x + y;)
    Print(Expression<'a>), // Basit bir print ifadesi (şimdilik)
    VarDeclaration { // Değişken bildirimi: let x = 10; veya let mut y: i32;
        name: Token<'a>, // Değişken adı
        initializer: Option<Expression<'a>>, // Opsiyonel başlangıç değeri
        mutable: bool, // `mut` anahtar kelimesi kullanıldı mı?
        type_annotation: Option<Token<'a>>, // Opsiyonel tür bildirimi (örn. : i32)
    },
    Block(sahne64::utils::Vec<Statement<'a>>), // Kod bloğu: { ... }
    If { // If ifadesi: if (koşul) { ... } else { ... }
        condition: Expression<'a>,
        then_branch: Box<Statement<'a>>,
        else_branch: Option<Box<Statement<'a>>>,
    },
    While { // While döngüsü: while (koşul) { ... }
        condition: Expression<'a>,
        body: Box<Statement<'a>>,
    },
    Return { // Return ifadesi: return value;
        keyword: Token<'a>, // 'return' token'ı
        value: Option<Expression<'a>>, // Opsiyonel dönüş değeri
    },
    Expression {
        expr: Expression<'a>,
        ty: Type, // İfade bildirimi için türü olabilir
    },
    Print {
        expr: Expression<'a>,
        ty: Type, // Print ifadesi için türü (genellikle Void)
    },
    VarDeclaration {
        name: Token<'a>,
        initializer: Option<Expression<'a>>,
        mutable: bool,
        type_annotation: Option<Token<'a>>,
        declared_type: Type, // Eklendi: Bu değişkenin kesinleşmiş türü
    },
    Block(sahne64::utils::Vec<Statement<'a>>),
    If {
        condition: Expression<'a>,
        then_branch: Box<Statement<'a>>,
        else_branch: Option<Box<Statement<'a>>>,
    },
    While {
        condition: Expression<'a>,
        body: Box<Statement<'a>>,
    },
    Return {
        keyword: Token<'a>,
        value: Option<Expression<'a>>,
        returned_type: Type, // Eklendi: Dönülen değerin türü
    },
    // Diğer bildirim türleri eklenebilir: Döngüler, sınıflar/structlar, enumlar vb.
}

#[derive(Debug, PartialEq, Clone)]
pub struct FunctionDeclaration<'a> {
    pub name: Token<'a>,
    pub parameters: sahne64::utils::Vec<Token<'a>>, // Parametreler hala Identifier token'ları, semantik analizde türleri atanacak.
    pub return_type_token: Option<Token<'a>>, // Parser'dan gelen ham tür token'ı
    pub resolved_return_type: Type, // Eklendi: Çözümlenmiş dönüş türü
    pub parameter_types: sahne64::utils::Vec<Type>, // Eklendi: Çözümlenmiş parametre türleri
    pub body: Statement<'a>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Program<'a> {
    pub functions: sahne64::utils::Vec<FunctionDeclaration<'a>>,
    pub statements: sahne64::utils::Vec<Statement<'a>>, // Global kapsamdaki bildirimler
}
