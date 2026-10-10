# تشغيل IQAWX 4.1

أداة بلغة Rust لتحليل البيانات، فك الترميزات والتشفير بالمفتاح، وفحص الشبكات. هذه نسخة IQAWX Lab 4.1.0 وليست أداة Chronos القديمة.

## تشغيل السورس على الماك

افتح Terminal داخل هذا المجلد الذي يحتوي `Cargo.toml`، ثم:

```sh
cargo run --release --locked
```

تظهر قائمة تفاعلية. للخروج اختر `8`. تحتاج Rust 1.93 أو أحدث وأدوات البناء للماك. البناء الأول ينزّل المكتبات من الإنترنت. لمعرفة إصدار Rust استخدم `rustc --version`. إذا ظهر خطأ أدوات البناء، ثبّت أدوات Apple الرسمية عبر `xcode-select --install` ثم أعد المحاولة.

لعرض جميع الأوامر:

```sh
cargo run --release --locked -- --help
```

لإنتاج ملف تشغيل:

```sh
cargo build --release --locked
./target/release/iqawx_lab
```

الملف الناتج يعمل على النظام والمعمارية اللذين بُني عليهما. الملف الجاهز المرفق بشكل منفصل باسم `iqawx_lab-macos-arm64` مخصص لماك Apple Silicon؛ لا يحتاج Cargo عند تشغيله.

## تجربة سريعة

```sh
cargo run --release --locked -- decode --format base64 --data ZmxhZ3tpcWF3eF9kZW1vfQ== --output-format text
```

النتيجة: `flag{iqawx_demo}`. هذا مثال تعليمي محضّر للعرض؛ Base64 ترميز يمكن عكسه بدون مفتاح، وليس تشفيراً حديثاً.

## فك تشفير بالمفتاح

```sh
cargo run --release --locked -- decrypt --algorithm aes128-ctr --input examples/aes128-ctr-ciphertext.hex --format hex --key-file examples/aes128-ctr-key.hex --key-format hex --nonce f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
```

النتيجة المتوقعة: `6bc1bee22e409f96e93d7e117393172a`. ملفات المفتاح هنا أمثلة اختبار علنية. عرضنا فك التشفير باستخدام المفتاح والعداد الصحيحين؛ لم نكسر AES.

## فحص محلي

```sh
cargo run --release --locked -- scan 127.0.0.1 --ports 8000,8001 --format json
```

النتيجة تتغيّر حسب الخدمات المفتوحة على جهازك. وجود منفذ مفتوح وحده لا يثبت وجود ثغرة.

## ماذا تدعم؟

فك Hex وBase64 وBase64url وBase32 وURL وBinary، استكشاف طبقات الترميز، تحليل ملفات وتخمينات Caesar وXOR، وفك أنواع AES وChaCha20 وRSA المدعومة بالمفتاح والمعاملات الصحيحة. كما تدعم TCP وUDP وIPv4 وIPv6 وCIDR وتقارير متعددة.

التخمينات ليست نتائج مؤكدة؛ تحليل المرشحات يأخذ أول 4096 بايت. الأداة لا تكسر كل التشفير ولا تسترجع النص من أي hash. الفحص الأصلي ليس Nmap كاملاً؛ أمر `nmap` يستدعي Nmap المثبت بصورة منفصلة. وضعا CBC وCTR لا يضمنان كشف المفتاح الخاطئ أو العبث بالبيانات.

