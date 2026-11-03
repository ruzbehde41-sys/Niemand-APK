# Niemand-APK

**Independent Android APK Research & Development**

A standalone repository for Android application development, authorized APK inspection, DEX/Smali/Java analysis, mobile tooling and reproducible Termux automation.

- [فارسی](#فارسی)
- [English](#english)

## English

### Scope
- Android application development and testing
- APK metadata and static inspection
- DEX, Smali and Java decompilation research
- Authorized reverse engineering for compatibility, debugging and interoperability
- Python and shell utilities for Android / Termux
- Reproducible reports, tests and documentation

### Repository layout
- `projects/`: independent Android, APK-analysis, reverse-engineering and mobile-tool projects
- `tools/`: toolchain notes and project-owned wrappers
- `scripts/`: portable automation
- `tests/`: automated tests
- `docs/`: workflow, toolchain and safety documentation
- `research/`: sourced research notes
- `templates/`: reusable reports

### Quick start
The scripts use the Python standard library and are read-only.

```sh
python scripts/apk_inventory.py /path/to/application.apk
sh scripts/check_environment.sh
python -m unittest discover -s tests -v
```

The inventory script hashes the input and reads ZIP metadata; it does not extract or execute APK contents.

### Safety and legal boundaries
Only inspect applications and data you own or are explicitly authorized to assess. Do not bypass authentication, access controls, DRM, payment protections or software licensing. Do not publish private data, credentials, signing keys or proprietary assets without permission. See [SECURITY.md](SECURITY.md) and [Safety and Legal](docs/SAFETY-AND-LEGAL.md).

### License
A project-wide license has not yet been selected. See [LICENSE-STATUS.md](LICENSE-STATUS.md). Third-party components retain their own licenses.

## فارسی

### هدف مخزن
این مخزن مستقل برای توسعه برنامه‌های اندروید، بررسی مجاز APK، تحلیل DEX و Smali و Java، ابزارهای موبایل و اتوماسیون قابل‌تکرار در Python و Termux است.

### ساختار
- `projects/`: پروژه‌های مستقل اندروید، تحلیل APK، مهندسی معکوس مجاز و ابزارهای موبایل
- `tools/`: مستندات ابزارها و اسکریپت‌های اختصاصی
- `scripts/`: اتوماسیون قابل‌حمل
- `tests/`: تست‌ها
- `docs/`: گردش‌کار، ابزارها و امنیت
- `research/`: یادداشت‌های پژوهشی همراه با منبع
- `templates/`: قالب گزارش‌ها

### شروع سریع
```sh
python scripts/apk_inventory.py /path/to/application.apk
sh scripts/check_environment.sh
python -m unittest discover -s tests -v
```

اسکریپت موجودی APK فقط هش و فراداده ZIP را می‌خواند؛ فایل را استخراج یا اجرا نمی‌کند.

### اصول امنیتی
فقط برنامه‌ها و داده‌هایی را بررسی کنید که مالک آن هستید یا مجوز صریح برای ارزیابی آن‌ها دارید. دور زدن احراز هویت، کنترل دسترسی، DRM یا مجوز نرم‌افزار خارج از محدوده این پروژه است. اطلاعات شخصی، کلید امضا و اسرار را منتشر نکنید.

### مجوز
هنوز مجوز سراسری برای مخزن انتخاب نشده است؛ وضعیت در [LICENSE-STATUS.md](LICENSE-STATUS.md) ثبت شده است.
