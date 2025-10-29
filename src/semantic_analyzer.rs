// semantic_analyzer.rs
#![no_std]

use crate::ast::{Program, FunctionDeclaration, Statement, Expression};
use crate::token::{Token, TokenKind};
use crate::error::{SemanticError, CompilerError, Result};
use crate::symbol_table::{SymbolTable, Symbol};
use crate::type_system::Type;
use sahne64::{print, println, eprintln}; // Konsol çıktıları için

pub struct SemanticAnalyzer<'a> {
    symbol_table: SymbolTable,
    /// Mevcut fonksiyonun dönüş türünü tutar. `return` ifadelerinin kontrolü için kullanılır.
    current_function_return_type: Type,
    /// Mevcut kapsamda bir döngü içinde olup olmadığımızı gösterir. `break`/`continue` kontrolü için.
    in_loop: bool,
    _phantom: core::marker::PhantomData<&'a ()>, // 'a lifetime'ı kullanmak için
}

impl<'a> SemanticAnalyzer<'a> {
    pub fn new() -> Self {
        SemanticAnalyzer {
            symbol_table: SymbolTable::new(),
            current_function_return_type: Type::Void, // Varsayılan olarak void
            in_loop: false,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Programın anlamsal analizini başlatır.
    /// Başarılı olursa, tür bilgisiyle zenginleştirilmiş bir AST veya benzer bir yapı döndürür.
    pub fn analyze(&mut self, program: &Program<'a>) -> Result<Program<'a>> {
        println!("Anlamsal analiz başlatıldı.");
        let mut analyzed_program = program.clone(); // AST'yi kopyalayarak üzerinde değişiklik yapalım

        // Fonksiyon prototiplerini global kapsamda tanımla (birbirlerini çağırabilmeleri için)
        for func_decl in analyzed_program.functions.iter_mut() {
            let func_name_str = func_decl.name.lexeme;
            if self.symbol_table.resolve_current_scope(func_name_str).is_some() {
                return Err(CompilerError::Semantic(SemanticError::UndefinedVariable { // Daha spesifik bir hata türü olabilir: RedefinedSymbol
                    name: sahne64::utils::String::from(func_name_str),
                    line: func_decl.name.line,
                    column: func_decl.name.column,
                }));
            }

            let resolved_return_type = func_decl.return_type_token
                .as_ref()
                .map_or(Type::Void, |t| Type::from_str(t.lexeme));

            let mut parameter_types = sahne64::utils::Vec::new();
            for param_token in func_decl.parameters.iter() {
                // Şimdilik parametre türlerini varsayımsal olarak Integer yapalım.
                // Gerçek dilde, parametrelerin de tür açıklamaları olurdu.
                parameter_types.push(Type::Integer); // Varsayılan parametre türü
            }

            // Fonksiyon sembolünü sembol tablosuna ekle
            self.symbol_table.define(
                sahne64::utils::String::from(func_name_str),
                Symbol {
                    name: sahne64::utils::String::from(func_name_str),
                    ty: Type::Void, // Fonksiyon türü daha karmaşık olabilir
                    is_mutable: false, // Fonksiyonlar mutable değildir
                    is_initialized: true,
                },
            );

            // Fonksiyon bildirimine çözümlenmiş türleri ata
            func_decl.resolved_return_type = resolved_return_type;
            func_decl.parameter_types = parameter_types;
        }


        // Global kapsamdaki bildirimleri analiz et
        let mut analyzed_global_statements = sahne64::utils::Vec::new();
        for stmt in analyzed_program.statements.iter() {
            analyzed_global_statements.push(self.analyze_statement(stmt)?);
        }
        analyzed_program.statements = analyzed_global_statements;


        // Fonksiyon gövdelerini analiz et
        for func_decl in analyzed_program.functions.iter_mut() {
            self.symbol_table.enter_scope(); // Fonksiyon kapsamına gir

            // Fonksiyon parametrelerini sembol tablosuna ekle
            for (idx, param_token) in func_decl.parameters.iter().enumerate() {
                let param_name = param_token.lexeme;
                // Parametrenin türünü func_decl.parameter_types'tan al.
                let param_type = func_decl.parameter_types[idx].clone();

                if self.symbol_table.resolve_current_scope(param_name).is_some() {
                    return Err(CompilerError::Semantic(SemanticError::UndefinedVariable { // Parametre ismi çakışması
                        name: sahne64::utils::String::from(param_name),
                        line: param_token.line,
                        column: param_token.column,
                    }));
                }
                self.symbol_table.define(
                    sahne64::utils::String::from(param_name),
                    Symbol {
                        name: sahne64::utils::String::from(param_name),
                        ty: param_type,
                        is_mutable: false, // Parametreler varsayılan olarak immutable
                        is_initialized: true,
                    },
                );
            }

            self.current_function_return_type = func_decl.resolved_return_type.clone();
            func_decl.body = self.analyze_statement(&func_decl.body)?; // Fonksiyon gövdesini analiz et

            self.symbol_table.exit_scope(); // Fonksiyon kapsamından çık
        }

        println!("Anlamsal analiz tamamlandı.");
        Ok(analyzed_program)
    }

    /// Bir ifadeyi analiz eder ve türünü döndürür.
    fn analyze_expression(&mut self, expr: &Expression<'a>) -> Result<Expression<'a>> {
        let mut analyzed_expr = expr.clone(); // AST düğümünü kopyalayarak üzerinde değişiklik yapalım

        match analyzed_expr {
            Expression::Literal { ref mut token, ref mut ty } => {
                *ty = match token.kind {
                    TokenKind::Integer => Type::Integer,
                    TokenKind::String => Type::String,
                    TokenKind::True | TokenKind::False => Type::Boolean,
                    _ => {
                        return Err(CompilerError::Semantic(SemanticError::TypeMismatch { // Daha spesifik olabilir
                            expected: "Literal".to_string(),
                            found: token.kind.to_string(),
                            line: token.line,
                            column: token.column,
                        }));
                    }
                };
            }
            Expression::Identifier { ref mut token, ref mut ty } => {
                let name = token.lexeme;
                if let Some(symbol) = self.symbol_table.resolve(name) {
                    *ty = symbol.ty.clone(); // Sembol tablosundan türü al
                } else {
                    return Err(CompilerError::Semantic(SemanticError::UndefinedVariable {
                        name: sahne64::utils::String::from(name),
                        line: token.line,
                        column: token.column,
                    }));
                }
            }
            Expression::Binary { ref mut left, ref operator, ref mut right, ref mut ty } => {
                *left = Box::new(self.analyze_expression(left)?);
                *right = Box::new(self.analyze_expression(right)?);

                let left_type = &left.get_type();
                let right_type = &right.get_type();

                // Basit tür kontrolü:
                *ty = match operator.kind {
                    TokenKind::Plus | TokenKind::Minus | TokenKind::Star | TokenKind::Slash => {
                        // Aritmetik operasyonlar sadece Integer üzerinde çalışır
                        if left_type == &Type::Integer && right_type == &Type::Integer {
                            Type::Integer
                        } else {
                            return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                                expected: "Integer".to_string(),
                                found: format!("{} ve {}", left_type.to_string(), right_type.to_string()),
                                line: operator.line,
                                column: operator.column,
                            }));
                        }
                    }
                    TokenKind::EqEq | TokenKind::BangEq | TokenKind::Lt | TokenKind::LtEq | TokenKind::Gt | TokenKind::GtEq => {
                        // Karşılaştırma operasyonları aynı türde olmalı ve Boolean döner
                        if left_type.is_compatible(right_type) {
                            Type::Boolean
                        } else {
                            return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                                expected: format!("Uyumlu türler (örn. {})", left_type.to_string()),
                                found: format!("{} ve {}", left_type.to_string(), right_type.to_string()),
                                line: operator.line,
                                column: operator.column,
                            }));
                        }
                    }
                    TokenKind::And | TokenKind::Or => {
                        // Mantıksal operasyonlar sadece Boolean üzerinde çalışır
                        if left_type == &Type::Boolean && right_type == &Type::Boolean {
                            Type::Boolean
                        } else {
                            return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                                expected: "Boolean".to_string(),
                                found: format!("{} ve {}", left_type.to_string(), right_type.to_string()),
                                line: operator.line,
                                column: operator.column,
                            }));
                        }
                    }
                    _ => Type::Error, // Bilinmeyen operatör türü
                };
            }
            Expression::Unary { ref operator, ref mut right, ref mut ty } => {
                *right = Box::new(self.analyze_expression(right)?);
                let right_type = &right.get_type();

                *ty = match operator.kind {
                    TokenKind::Minus => { // Negatif operatör sadece Integer üzerinde çalışır
                        if right_type == &Type::Integer {
                            Type::Integer
                        } else {
                            return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                                expected: "Integer".to_string(),
                                found: right_type.to_string(),
                                line: operator.line,
                                column: operator.column,
                            }));
                        }
                    }
                    TokenKind::Bang => { // Mantıksal NOT operatörü sadece Boolean üzerinde çalışır
                        if right_type == &Type::Boolean {
                            Type::Boolean
                        } else {
                            return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                                expected: "Boolean".to_string(),
                                found: right_type.to_string(),
                                line: operator.line,
                                column: operator.column,
                            }));
                        }
                    }
                    _ => Type::Error, // Bilinmeyen operatör türü
                };
            }
            Expression::Call { ref mut callee, ref paren, ref mut arguments, ref mut ty } => {
                *callee = Box::new(self.analyze_expression(callee)?);
                // Fonksiyon çağrısı callee'nin türü Function Type olmalı (şimdilik Identifier kabul ediyoruz)
                if let Expression::Identifier { token: callee_token, ty: callee_ty } = &**callee {
                    let func_name = callee_token.lexeme;
                    if let Some(symbol) = self.symbol_table.resolve(func_name) {
                        // Sembol tablosunda fonksiyonun dönüş türünü ve parametre türlerini bulmalıyız.
                        // Şimdilik varsayımsal olarak her çağrı için dönüş türünü Void yapalım.
                        // Gerçek bir dilde, fonksiyonun türü Symbol'de saklanırdı.
                        // func_ty = symbol.ty; // Eğer Symbol içinde Function Type saklanıyorsa

                        // Basitlik için: Fonksiyonun dönüş türü şimdilik hardcoded.
                        // İleride Function Symbol'den alınacak.
                        *ty = Type::Integer; // Varsayımsal dönüş türü.
                        
                        // Argümanların türlerini analiz et ve parametrelerle karşılaştır (şimdilik kontrol yok)
                        let mut analyzed_args = sahne64::utils::Vec::new();
                        for arg in arguments.iter() {
                            analyzed_args.push(self.analyze_expression(arg)?);
                        }
                        *arguments = analyzed_args;

                        // TODO: Argüman sayısı ve türlerinin fonksiyon tanımıyla eşleşip eşleşmediğini kontrol et.
                        // Bu kısım için Symbol'de fonksiyonun parametre türleri ve dönüş türü saklanmalı.
                        // Örneğin: `symbol.ty` bir `Type::Function` enum'ı olabilir.

                    } else {
                        return Err(CompilerError::Semantic(SemanticError::UndefinedVariable {
                            name: sahne64::utils::String::from(func_name),
                            line: callee_token.line,
                            column: callee_token.column,
                        }));
                    }
                } else {
                    return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                        expected: "Fonksiyon adı veya çağrılabilir ifade".to_string(),
                        found: callee.get_type().to_string(),
                        line: paren.line,
                        column: paren.column,
                    }));
                }
            }
            Expression::Grouping { ref mut expression, ref mut ty } => {
                *expression = Box::new(self.analyze_expression(expression)?);
                *ty = expression.get_type();
            }
            Expression::Assign { ref name, ref mut value, ref mut ty } => {
                *value = Box::new(self.analyze_expression(value)?);
                let value_type = value.get_type();

                // Atama hedefi bir identifier olmalı
                if let Some(symbol) = self.symbol_table.resolve_mut(name.lexeme) {
                    if !symbol.is_mutable {
                        return Err(CompilerError::Semantic(SemanticError::TypeMismatch { // Daha spesifik hata: ImmutableVariableAssignment
                            expected: "Değiştirilebilir değişken".to_string(),
                            found: format!("Değiştirilemez değişken '{}'", name.lexeme),
                            line: name.line,
                            column: name.column,
                        }));
                    }
                    if !symbol.ty.is_compatible(&value_type) {
                        return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                            expected: symbol.ty.to_string(),
                            found: value_type.to_string(),
                            line: name.line,
                            column: name.column,
                        }));
                    }
                    symbol.is_initialized = true; // Atandığı için initialized oldu
                    *ty = value_type; // Atama ifadesinin türü, atanan değerin türüdür
                } else {
                    return Err(CompilerError::Semantic(SemanticError::UndefinedVariable {
                        name: sahne64::utils::String::from(name.lexeme),
                        line: name.line,
                        column: name.column,
                    }));
                }
            }
        }
        Ok(analyzed_expr)
    }

    /// Bir bildirimi analiz eder.
    fn analyze_statement(&mut self, stmt: &Statement<'a>) -> Result<Statement<'a>> {
        let mut analyzed_stmt = stmt.clone(); // AST düğümünü kopyalayarak üzerinde değişiklik yapalım

        match analyzed_stmt {
            Statement::Expression { ref mut expr, ref mut ty } => {
                *expr = self.analyze_expression(expr)?;
                *ty = expr.get_type();
            }
            Statement::Print { ref mut expr, ref mut ty } => {
                *expr = self.analyze_expression(expr)?;
                // Print ifadesinin türü genellikle void'dir.
                *ty = Type::Void;
            }
            Statement::VarDeclaration { ref name, ref mut initializer, mutable, ref type_annotation, ref mut declared_type } => {
                let initial_type = if let Some(init_expr) = initializer {
                    let analyzed_init = self.analyze_expression(init_expr)?;
                    *initializer = Some(analyzed_init.clone());
                    analyzed_init.get_type()
                } else {
                    Type::Unknown // Başlangıç değeri yoksa türü bilinmiyor
                };

                // Eğer tür bildirimi varsa, onu çöz.
                let annotated_type = if let Some(anno_token) = type_annotation {
                    Type::from_str(anno_token.lexeme)
                } else {
                    Type::Unknown // Tür bildirimi yok
                };

                // Tür çıkarımı veya kontrolü
                let final_type = if annotated_type != Type::Unknown {
                    // Tür bildirimi varsa, başlangıç değeriyle uyumlu mu?
                    if initial_type != Type::Unknown && !initial_type.is_compatible(&annotated_type) {
                        return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                            expected: annotated_type.to_string(),
                            found: initial_type.to_string(),
                            line: name.line,
                            column: name.column,
                        }));
                    }
                    annotated_type
                } else if initial_type != Type::Unknown {
                    // Sadece başlangıç değeri varsa, türü ondan çıkar.
                    initial_type
                } else {
                    // Ne tür bildirimi ne de başlangıç değeri varsa hata (veya varsayılan tür)
                    return Err(CompilerError::Semantic(SemanticError::TypeMismatch { // Daha spesifik hata: MissingTypeAnnotationOrInitializer
                        expected: "Tür bildirimi veya başlangıç değeri".to_string(),
                        found: format!("Değişken '{}'", name.lexeme),
                        line: name.line,
                        column: name.column,
                    }));
                };
                *declared_type = final_type.clone();

                // Sembol tablosuna değişkeni ekle
                if self.symbol_table.resolve_current_scope(name.lexeme).is_some() {
                    return Err(CompilerError::Semantic(SemanticError::UndefinedVariable { // Daha spesifik hata: RedefinedVariable
                        name: sahne64::utils::String::from(name.lexeme),
                        line: name.line,
                        column: name.column,
                    }));
                }
                self.symbol_table.define(
                    sahne64::utils::String::from(name.lexeme),
                    Symbol {
                        name: sahne64::utils::String::from(name.lexeme),
                        ty: final_type,
                        is_mutable: mutable,
                        is_initialized: initializer.is_some(),
                    },
                );
            }
            Statement::Block(ref mut statements) => {
                self.symbol_table.enter_scope(); // Yeni blok kapsamına gir
                let mut analyzed_block_statements = sahne64::utils::Vec::new();
                for stmt in statements.iter() {
                    analyzed_block_statements.push(self.analyze_statement(stmt)?);
                }
                *statements = analyzed_block_statements;
                self.symbol_table.exit_scope(); // Blok kapsamından çık
            }
            Statement::If { ref mut condition, ref mut then_branch, ref mut else_branch } => {
                *condition = self.analyze_expression(condition)?;
                if condition.get_type() != Type::Boolean {
                    return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                        expected: "Boolean".to_string(),
                        found: condition.get_type().to_string(),
                        line: condition.get_token_location().line,
                        column: condition.get_token_location().column,
                    }));
                }
                *then_branch = Box::new(self.analyze_statement(then_branch)?);
                if let Some(else_stmt) = else_branch {
                    *else_branch = Some(Box::new(self.analyze_statement(else_stmt)?));
                }
            }
            Statement::While { ref mut condition, ref mut body } => {
                *condition = self.analyze_expression(condition)?;
                if condition.get_type() != Type::Boolean {
                    return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                        expected: "Boolean".to_string(),
                        found: condition.get_type().to_string(),
                        line: condition.get_token_location().line,
                        column: condition.get_token_location().column,
                    }));
                }
                self.in_loop = true; // Döngü kapsamına gir
                *body = Box::new(self.analyze_statement(body)?);
                self.in_loop = false; // Döngü kapsamından çık
            }
            Statement::Return { ref keyword, ref mut value, ref mut returned_type } => {
                let return_value_type = if let Some(expr) = value {
                    let analyzed_expr = self.analyze_expression(expr)?;
                    *value = Some(analyzed_expr.clone());
                    analyzed_expr.get_type()
                } else {
                    Type::Void // Değer dönülmüyorsa Void
                };
                *returned_type = return_value_type.clone();

                // Fonksiyonun dönüş türüyle uyumlu mu?
                if !return_value_type.is_compatible(&self.current_function_return_type) {
                    return Err(CompilerError::Semantic(SemanticError::TypeMismatch {
                        expected: self.current_function_return_type.to_string(),
                        found: return_value_type.to_string(),
                        line: keyword.line,
                        column: keyword.column,
                    }));
                }
            }
        }
        Ok(analyzed_stmt)
    }
}

// AST düğümlerine hızlı tür erişimi için helper metotlar (ast.rs'ye eklenebilir)
// Bu metotları AST düğümüne eklemek daha temiz olacaktır.
impl<'a> Expression<'a> {
    pub fn get_type(&self) -> Type {
        match self {
            Expression::Literal { ty, .. } => ty.clone(),
            Expression::Identifier { ty, .. } => ty.clone(),
            Expression::Binary { ty, .. } => ty.clone(),
            Expression::Unary { ty, .. } => ty.clone(),
            Expression::Call { ty, .. } => ty.clone(),
            Expression::Grouping { ty, .. } => ty.clone(),
            Expression::Assign { ty, .. } => ty.clone(),
        }
    }

    pub fn get_token_location(&self) -> &Token<'a> {
        match self {
            Expression::Literal { token, .. } => token,
            Expression::Identifier { token, .. } => token,
            Expression::Binary { operator, .. } => operator, // Operatörün konumu
            Expression::Unary { operator, .. } => operator,   // Operatörün konumu
            Expression::Call { paren, .. } => paren, // Parantezin konumu
            Expression::Grouping { expression, .. } => expression.get_token_location(),
            Expression::Assign { name, .. } => name,
        }
    }
}

impl<'a> Statement<'a> {
    pub fn get_type(&self) -> Type {
        match self {
            Statement::Expression { ty, .. } => ty.clone(),
            Statement::Print { ty, .. } => ty.clone(),
            _ => Type::Void, // Diğer bildirimler genellikle Void türündedir
        }
    }
}
