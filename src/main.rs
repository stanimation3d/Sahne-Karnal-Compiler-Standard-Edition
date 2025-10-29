#![no_std] // Sahne Karnal hedef alındığı için standart kütüphaneye ihtiyacımız yok
#![no_main] // Kendi giriş noktamızı tanımlayacağız

// Sahne64 sistem çağrılarını kullanabilmek için sahne64 kütüphanesini içe aktaralım
// Bu kütüphane, daha önce konuştuğumuz syscall arayüzlerini içeriyor.
#[macro_use] // print! ve println! gibi makrolar için (eğer stdio_impl modülünü kullanırsak)
extern crate sahne64;

// Diğer derleyici modüllerimizi şimdilik boş olarak tanımlayalım.
// Bu modüller ilerledikçe doldurulacak.
mod lexer;
mod parser;
mod ast;
mod ir;
mod semantic_analyzer;
mod codegen;
mod target;
mod assembler;
mod sohfig; // Muhtemelen global yapılandırma veya yardımcılar
mod token;
mod error;
mod symbol_table;
mod type_system;
mod utils;
mod error_reporter;

// Sahne Karnal'ın giriş noktası (genellikle _start)
// `no_mangle` ile isminin bozulmamasını sağlıyoruz ki çekirdek doğru çağırabilsin.
// `extern "C"` ile C ABI'sını kullanıyoruz, zira çekirdek muhtemelen bu şekilde bekler.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Çekirdeğin bize verdiği komut satırı argümanlarını almak için bir mekanizma olmalı.
    // Şimdilik varsayımsal olarak sabit argümanlar kullanacağız veya bir syscall ile alacağız.
    // Gerçek bir senaryoda, çekirdek genellikle args ve envp'yi stack'e pushlar
    // veya özel bir sistem çağrısı sağlar.
    // Şimdilik basitlik için bir argüman işleme döngüsü ekleyelim.

    // Basit bir test: konsola yazı yazalım
    println!("Sahne Derleyici Başlatıldı!");

    // Örnek argümanlar (gerçekte çekirdekten alınacak)
    // Şu an için elle verelim, daha sonra çekirdek entegrasyonu yaparız.
    // Sahne Karnal'dan argümanları almanın gerçek yolu Karnal64'ün ABI'sine bağlıdır.
    // Genellikle task::spawn ile gönderilen args slice'ını kullanırız veya bir syscall ile.
    // Basit bir örnek için, geçici olarak 'argv' dizisini simüle edelim.
    let args_str = "-target riscv64 -optimize sahne_and_karnal -input_file /app/source.sn -output_file /app/output.bin";
    let mut args_iter = args_str.split_whitespace();

    let mut target_arch: Option<&str> = None;
    let mut optimization_level: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut output_file: Option<&str> = None;
    let mut compile_mode_kernel_only = false; // Varsayılan: Kullanıcı alanı derlemesi

    // Basit bir argüman ayrıştırma döngüsü
    while let Some(arg) = args_iter.next() {
        match arg {
            "-target" => {
                if let Some(arch) = args_iter.next() {
                    target_arch = Some(arch);
                } else {
                    eprintln!("Hata: -target için mimari belirtilmedi.");
                    task::exit(1);
                }
            }
            "-optimize" => {
                if let Some(opt_level) = args_iter.next() {
                    optimization_level = Some(opt_level);
                    if opt_level == "-karnal_only" {
                        compile_mode_kernel_only = true;
                    }
                } else {
                    eprintln!("Hata: -optimize için seviye belirtilmedi.");
                    task::exit(1);
                }
            }
            "-input_file" => {
                if let Some(file) = args_iter.next() {
                    input_file = Some(file);
                } else {
                    eprintln!("Hata: -input_file için dosya adı belirtilmedi.");
                    task::exit(1);
                }
            }
            "-output_file" => {
                if let Some(file) = args_iter.next() {
                    output_file = Some(file);
                } else {
                    eprintln!("Hata: -output_file için dosya adı belirtilmedi.");
                    task::exit(1);
                }
            }
            _ => {
                eprintln!("Uyarı: Bilinmeyen argüman: {}", arg);
            }
        }
    }

    // Gerekli argümanların kontrolü
    let (Some(target_arch), Some(optimization_level), Some(input_file), Some(output_file)) =
        (target_arch, optimization_level, input_file, output_file) else {
        eprintln!("Hata: Eksik derleyici argümanları.");
        task::exit(1);
    };


    println!("Derleme Hedefi: {}", target_arch);
    println!("Optimizasyon Seviyesi: {}", optimization_level);
    println!("Giriş Dosyası: {}", input_file);
    println!("Çıkış Dosyası: {}", output_file);
    println!("Derleme Modu: {}", if compile_mode_kernel_only { "Kernel Alanı (Karnal64 Syscalls)" } else { "Kullanıcı Alanı (Sahne64 & Karnal64 Syscalls)" });

    // --- Derleme Süreci Aşamaları ---

    // 1. Kaynak Kodu Oku (resource modülü ile)
    // Şimdilik sadece dosya yolunu yazdıralım, gerçek okuma ileriki aşamalarda.
    println!("Kaynak kod okunuyor: {}", input_file);
    let source_handle = match sahne64::resource::acquire(input_file, sahne64::resource::MODE_READ) {
        Ok(handle) => {
            println!("Giriş dosyası handle'ı alındı.");
            handle
        },
        Err(e) => {
            eprintln!("Hata: Giriş dosyası '{}' okunamadı: {:?}", input_file, e);
            task::exit(1);
        }
    };

    // Büyük kaynak kodları için uygun bir tampon boyutu belirleyelim (örn. 4KB)
    let mut source_buffer = [0u8; 4096];
    let mut total_bytes_read = 0;
    let mut full_source_code = sahne64::utils::Vec::new(); // Dinamik büyüklükte bir vektör (no_std uyumlu)

    loop {
        match sahne64::resource::read(source_handle, &mut source_buffer) {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    // Dosya sonu
                    break;
                }
                full_source_code.extend_from_slice(&source_buffer[..bytes_read]);
                total_bytes_read += bytes_read;
            },
            Err(sahne64::SahneError::WouldBlock) => {
                // Non-blocking ise bekleyebiliriz veya başka iş yapabiliriz.
                // Basitlik için bir süre uyuyalım veya yield edelim.
                sahne64::task::yield_now().expect("Task yield failed");
            },
            Err(e) => {
                eprintln!("Hata: Kaynak okuma hatası: {:?}", e);
                sahne64::resource::release(source_handle).expect("Kaynak serbest bırakılamadı");
                task::exit(1);
            }
        }
    }
    sahne64::resource::release(source_handle).expect("Giriş kaynağı serbest bırakılamadı.");
    
    let source_code = match core::str::from_utf8(&full_source_code) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Hata: Kaynak kod geçerli UTF-8 değil.");
            task::exit(1);
        }
    };
    println!("{} byte kaynak kod okundu.", total_bytes_read);
    // println!("Okunan kaynak kod:\n{}", source_code); // Hata ayıklama için

    // 2. Sözcüksel Analiz (Lexer)
    println!("Sözcüksel analiz (lexing) yapılıyor...");
    let mut lexer = lexer::Lexer::new(source_code);
    let tokens = match lexer.tokenize() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Sözcüksel hata: {:?}", e);
            error_reporter::report_lexing_error(&e, source_code); // Hata raporlama
            task::exit(1);
        }
    };
    println!("Token sayısı: {}", tokens.len());
     for token in tokens.iter() {
         println!("{:?}", token); // Hata ayıklama için
     }

    // 3. Sözdizimsel Analiz (Parser)
    println!("Sözdizimsel analiz (parsing) yapılıyor...");
    let mut parser = parser::Parser::new(tokens);
    let ast = match parser.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Sözdizimsel hata: {:?}", e);
            error_reporter::report_parsing_error(&e, source_code); // Hata raporlama
            task::exit(1);
        }
    };
    println!("AST oluşturuldu.");
     ast.print_debug(); // Hata ayıklama için

    // 4. Semantik Analiz
    println!("Semantik analiz yapılıyor...");
    let mut analyzer = semantic_analyzer::SemanticAnalyzer::new();
    let typed_ast = match analyzer.analyze(&ast) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Semantik hata: {:?}", e);
            error_reporter::report_semantic_error(&e, source_code); // Hata raporlama
            task::exit(1);
        }
    };
    println!("Semantik analiz tamamlandı.");

    // 5. Ara Temsil (IR) Üretimi
    println!("Ara temsil (IR) üretiliyor...");
    let ir_module = ir::IRGenerator::new().generate(&typed_ast);
    println!("IR modülü oluşturuldu.");

    // 6. Kod Üretimi (Codegen)
    println!("Hedef makine kodu üretiliyor...");
    // `target` modülü, seçilen mimariye özel ayarları sağlayacak.
    let target_info = target::TargetInfo::new(target_arch, compile_mode_kernel_only);
    let mut codegen = codegen::Codegen::new(target_info);
    let assembly_code = codegen.generate_code(&ir_module);
    println!("Makine kodu üretimi tamamlandı.");

    // 7. Assembler/Linker
    println!("Assembly kodu ikiliye dönüştürülüyor...");
    let compiled_binary = assembler::Assembler::new().assemble(&assembly_code);
    println!("İkili derleme tamamlandı. Boyut: {} byte.", compiled_binary.len());

    // 8. Çıkış Dosyasına Yazma
    println!("Derlenmiş ikili dosya yazılıyor: {}", output_file);
    let output_handle = match sahne64::resource::acquire(output_file, sahne64::resource::MODE_WRITE | sahne64::resource::MODE_CREATE | sahne64::resource::MODE_TRUNCATE) {
        Ok(handle) => {
            println!("Çıkış dosyası handle'ı alındı.");
            handle
        },
        Err(e) => {
            eprintln!("Hata: Çıkış dosyası '{}' yazılamadı: {:?}", output_file, e);
            task::exit(1);
        }
    };

    match sahne64::resource::write(output_handle, &compiled_binary) {
        Ok(bytes_written) => println!("{} byte çıkış dosyasına yazıldı.", bytes_written),
        Err(e) => eprintln!("Hata: Çıkış dosyasına yazma hatası: {:?}", e),
    }

    sahne64::resource::release(output_handle).expect("Çıkış kaynağı serbest bırakılamadı.");

    println!("Derleme Başarılı!");

    // Görevden çıkış (geri dönmez)
    sahne64::task::exit(0);
}

// panic handler ve stdio_impl modülü Sahne64 kütüphanesi içinde bulunuyor olmalı.
// Eğer bulunmuyorsa, burada yeniden tanımlanmaları gerekir.
// Örneğin:

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    eprintln!("Derleyici Panic: {:?}", _info);
    // Çekirdeğe uygun bir hata kodu ile çıkış
    sahne64::task::exit(1);
}

// Bu kısım sahne64 kütüphanesinin kendisinde tanımlı olmalı, aksi halde burada ihtiyaç duyulur.
// stdio_impl modülü, print! ve println! makrolarını no_std ortamında kullanabilmek için
// çekirdek konsol kaynağına yazma işlevselliğini sağlar.
#[cfg(not(feature = "std"))] // Sadece no_std ortamı için
mod stdio_impl {
    use sahne64::resource;
    use sahne64::Handle;
    use sahne64::SahneError;
    use core::fmt::{self, Write};

    // Sahne Karnal'daki konsol kaynağının Handle'ı (varsayımsal olarak sabit bir değer veya syscall ile alınır)
    // Genellikle çekirdek, görev başlatıldığında varsayılan stdin/stdout handle'larını sağlar.
    // Şimdilik, 1 numaralı handle'ı standart çıktı (stdout) olarak kabul edelim.
    // Gerçekte bu, task::spawn içinde initial_handles ile veya bir bootstrap mekanizmasıyla sağlanır.
    const STDOUT_HANDLE: Handle = Handle(1);
    const STDERR_HANDLE: Handle = Handle(2); // Varsayımsal standart hata çıktısı

    struct ConsoleWriter {
        handle: Handle,
    }

    impl Write for ConsoleWriter {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            // Write to the console resource
            match resource::write(self.handle, s.as_bytes()) {
                Ok(_) => Ok(()),
                // Hata durumunda, fmt::Error döndür.
                Err(_) => Err(fmt::Error),
            }
        }
    }

    #[doc(hidden)]
    pub fn _print(args: fmt::Arguments) {
        let mut writer = ConsoleWriter { handle: STDOUT_HANDLE };
        writer.write_fmt(args).expect("Konsola yazma hatası!");
    }

    #[doc(hidden)]
    pub fn _eprint(args: fmt::Arguments) {
        let mut writer = ConsoleWriter { handle: STDERR_HANDLE };
        writer.write_fmt(args).expect("Hata konsola yazma hatası!");
    }

    #[macro_export]
    macro_rules! print {
        ($($arg:tt)*) => ({
            $crate::stdio_impl::_print(format_args!($($arg)*));
        });
    }

    #[macro_export]
    macro_rules! println {
        () => ($crate::print!("\n"));
        ($($arg:tt)*) => ({
            $crate::stdio_impl::_print(format_args!($($arg)*));
            $crate::print!("\n");
        });
    }

    #[macro_export]
    macro_rules! eprintln {
        () => ($crate::eprint!("\n"));
        ($($arg:tt)*) => ({
            $crate::stdio_impl::_eprint(format_args!($($arg)*));
            $crate::eprint!("\n");
        });
    }
}
