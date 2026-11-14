# IQAWX Lab 4.2 — أداة الطرفية

أداة لفحص الشبكات وتحليل البيانات وفك الترميزات وفك التشفير بالمفتاح الصحيح. ثبّتها مرة واحدة، وبعدها شغّلها من أي طرفية بالأمر **`iqaw`**. النسخة العامة تعمل بالكامل داخل الترمنل.

[English documentation](README.md)

## التثبيت من السورس

تحتاج Git و[Rust 1.93 أو أحدث](https://rust-lang.org/tools/install) وأدوات البناء الخاصة بنظامك. التثبيت الأول ينزّل المكتبات ويبني البرنامج مرة واحدة؛ بعدها لا تحتاج كتابة أوامر Cargo كلما أردت تشغيل الأداة.

### ماك ولينكس

افتح Terminal واكتب:

```sh
git clone https://github.com/iqawx/iqawx-lab.git
cd iqawx-lab
sh scripts/install.sh
```

المثبت يضع الأمر داخل `~/.local/bin` ويضيفه إلى مسار التشغيل في إعدادات sh أو Bash أو Zsh، ولا يحتاج صلاحيات مسؤول. **افتح نافذة طرفية جديدة بعد التثبيت.**

### ويندوز

ثبّت Rust وأدوات بناء C++، ثم افتح PowerShell واكتب:

```powershell
git clone https://github.com/iqawx/iqawx-lab.git
cd iqawx-lab
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

يوضع `iqaw.exe` داخل `%LOCALAPPDATA%\IQAWX\bin` ويضاف هذا المجلد إلى PATH الخاص بحسابك. أغلق تطبيق الطرفية وافتحه من جديد بعد التثبيت. الاستثناء لسياسة PowerShell خاص بعملية المثبت الحالية فقط.

## التشغيل اليومي والاختصارات

فتح القائمة التفاعلية:

```sh
iqaw
```

أو نفس القائمة بصورة صريحة:

```sh
iqaw menu
```

اكتب رقم الخيار واضغط Enter. للخروج من القائمة اختر `8`. لإيقاف عملية جارية اضغط Ctrl+C.

عرض المساعدة والإصدار:

```sh
iqaw --help
iqaw --version
iqaw scan --help
iqaw decrypt --help
```

فحص منافذ جهازك مباشرة:

```sh
iqaw scan 127.0.0.1 -p 80,443
```

حفظ تقرير JSON:

```sh
iqaw scan 127.0.0.1 --ports 8000,8001 --format json --out report.json
```

النتيجة تعتمد على الخدمات الموجودة فعليًا. استبدال ملف نتائج موجود يتطلب `--force`. افحص أجهزتك أو الأنظمة التي تملك إذنًا بفحصها. الفحص الأصلي لا يحتاج Nmap؛ الأمر `iqaw nmap -- <args>` يحتاج تثبيت Nmap بشكل منفصل.

## فك الترميز

```sh
iqaw decode --format base64 --data ZmxhZ3tpcWF3eF9kZW1vfQ== --output-format text
```

النتيجة: `flag{iqawx_demo}`. هذا مثال تعليمي محضّر؛ Base64 ترميز قابل للعكس، وليس تشفيرًا حديثًا.

## فك التشفير بالمفتاح

من مجلد المستودع أو حزمة تحتوي مجلد `examples`:

```sh
iqaw decrypt --algorithm aes128-ctr --input examples/aes128-ctr-ciphertext.hex --format hex --key-file examples/aes128-ctr-key.hex --key-format hex --nonce f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
```

النتيجة المتوقعة: `6bc1bee22e409f96e93d7e117393172a`. المفتاح المرفق بيانات اختبار علنية. الأداة تستخدم المفتاح والعداد الصحيحين في هذا المثال.

## الحزم الجاهزة بدون Cargo

من [صفحة البناء في GitHub Actions](https://github.com/iqawx/iqawx-lab/actions/workflows/build.yml)، افتح تشغيلًا ناجحًا وحمّل الحزمة المناسبة لنظامك من قسم Artifacts: ماك Apple Silicon أو ماك Intel أو لينكس x64 أو ويندوز x64. فك ملف ZIP الخاص بالتنزيل، ثم فك الحزمة الموجودة بداخله. التشغيل الجاري أو الفاشل لا يمثل حزمة متحققة لذلك النظام.

شغّل المثبت الموجود داخل الحزمة، بنفس أمر التثبيت أعلاه:

```sh
sh scripts/install.sh
```

أو على ويندوز:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

الحزمة الجاهزة تحتوي `iqaw` أو `iqaw.exe` ولا تحتاج Rust أو Cargo للتثبيت أو التشغيل. افتح طرفية جديدة واكتب `iqaw`. يوجد أيضًا ملف فتح بالنقر المزدوج لماك `Open IQAWX.command` ولويندوز `Open IQAWX.cmd` لفتح أداة الطرفية. على لينكس يمكن تشغيل `./iqaw` من المجلد المستخرج. ملف SHA-256 المرافق يساعدك على التحقق من الأرشيف.

كل نظام له اختبار وبناء مستقل داخل GitHub Actions. الفحص المحلي تم على ماك Apple Silicon؛ راجع نتيجة البناء لنفس التعديل لمعرفة حالة ويندوز ولينكس وماك Intel.

## التحديث وحل مشكلة الأمر غير الموجود

إذا ثبّتّ من السورس، شغّل `git pull --ff-only` داخل المستودع ثم أعد تشغيل المثبت. للحزمة الجاهزة، حمّل حزمة أحدث وفكّها وشغّل مثبتها.

إذا لم تتعرف الطرفية على `iqaw`، أغلقها وافتحها من جديد وتأكد أن مجلد التثبيت مضاف إلى PATH. يمكن اختيار مجلد تثبيت خاص بدون تعديل إعدادات الطرفية:

```sh
sh scripts/install.sh --bin-dir /path/to/bin --no-path
```

```powershell
.\scripts\install.ps1 -InstallDir 'C:\path\to\bin' -NoPath
```

لإزالة التثبيت، احذف ملف التشغيل المثبّت وإضافة IQAWX من إعدادات PATH.

## القدرات والحدود

تدعم الأداة فك Hex وBase64 وBase64url وBase32 وURL وForm وBinary، واستكشاف طبقات الترميز، وتحليل الملفات والبصمات والنصوص والمرشحين، وCaesar وXOR، وفك خوارزميات AES وChaCha20 وRSA المدعومة بالمفتاح والمعاملات الصحيحة. وتدعم TCP وUDP وIPv4 وIPv6 وCIDR وتقارير نصية وJSON وXML وgrep.

تحليل المرشحين يستخدم أول 4096 بايت وقد يعطي نتائج خاطئة. الأداة لا تكسر التشفير الحديث عمومًا بدون مفتاح ولا تعكس الهاشات. الفحص الأصلي ليس تنفيذًا كاملًا لـNmap. وضعا CBC وCTR لا يصادقان على البيانات، وحد الإدخال 64 MiB. تحقّق من النتائج التخمينية بشكل مستقل.

## للمطورين

```sh
cargo build --release --locked --bins
cargo test --locked
./target/release/iqaw --help
```

على ويندوز مسار الملف الناتج هو `.\target\release\iqaw.exe`. يبقى ملف التشغيل الأصلي `iqawx_lab` موجودًا ضمن البناء والحزم للتوافق. أوامر Cargo هنا خاصة بالبناء والتطوير؛ التشغيل اليومي يكون بأمر `iqaw`.

تقارير [التحقق السابقة](VALIDATION.md) و[فحوص النشر السابقة](PUBLICATION_CHECKS.md) تحتفظ بنتائجها المؤرخة وحدود الأنظمة التي اختُبرت. مفاتيح الأمثلة ومفتاح RSA في الاختبارات بيانات تجريبية علنية، ولا تصلح للاستخدام الحقيقي.


## 4.2 updates / تحديثات 4.2

[Feature guide / دليل الميزات](GUIDE_4_2.md) · [English test report](TEST_REPORT_EN.md) · [تقرير الاختبار بالعربي](TEST_REPORT_AR.md)
