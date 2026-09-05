<p align="center">
  <img src="logo.png" width="160" alt="SS44 logo" />
</p>

<h1 align="center">🚀 SS44 — ساب هوشمند مخصوص ایران</h1>

<p align="center">
  <a href="STATS.md"><img src="https://img.shields.io/badge/status-auto--updated_30min-brightgreen" alt="auto updated" /></a>
  <img src="https://img.shields.io/badge/protocols-VLESS_VMess_Trojan_SS-blue" alt="protocols" />
  <img src="https://img.shields.io/badge/focus-Irancell_Iran-red" alt="irancell" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license" />
</p>

<p align="center">
  هر ۳۰ دقیقه از بهترین ساب‌های عمومی فچ می‌کند، تست اتصال می‌گیرد<br/>
  و فقط سالم‌ترین کانفیگ‌ها را با اسم <b>SS44-001</b> تا <b>SS44-120</b> منتشر می‌کند.
</p>

---

## ⚡ اتصال با یک کلیک | One-Click Subscribe

| 📱 برنامه | 📦 فرمت | 🔗 لینک سابسکریپشن |
|---|---|---|
| v2rayNG / Hiddify / NekoBox | 🥇 **GOLD — هندشیک TLS تأییدشده (اول اینو امتحان کن)** | `https://raw.githubusercontent.com/ZendanTeam/SS44-sub/main/SS44-gold.txt` |
| v2rayNG / Hiddify / NekoBox | معمولی (GOLD + SILVER) | `https://raw.githubusercontent.com/ZendanTeam/SS44-sub/main/SS44.txt` |
| v2rayNG / Shadowrocket | base64 | `https://raw.githubusercontent.com/ZendanTeam/SS44-sub/main/SS44-base64.txt` |
| Clash / ClashMeta / NekoBox | clash | `https://raw.githubusercontent.com/ZendanTeam/SS44-sub/main/SS44-clash.yaml` |
| Hiddify / NekoBox (تست دستی) | 🌀 Hysteria2 / TUIC (پروتکل UDP — وقتی VLESS جواب نمیده) | `https://raw.githubusercontent.com/ZendanTeam/SS44-sub/main/SS44-udp.txt` |

> لینک اول را در بخش **Subscription** برنامه بگذار و Update بزن. از این به بعد خودش همیشه تازه است.

## ✨ چرا SS44؟ | Why SS44?

| ویژگی | SS44 | ساب‌های معمولی |
|---|---|---|
| 🇮🇷 رتبه‌بندی مخصوص ایرانسل (Reality + پورت 443 اول) | ✅ | ❌ |
| 🧹 حذف آی‌پی خصوصی/لوپ‌بک و تکراری‌ها | ✅ | ❌ |
| 🔍 دیکد و تست واقعی VMess (نه فقط VLESS) | ✅ | ❌ |
| 📦 سه خروجی همزمان (txt + base64 + clash) | ✅ | بعضی |
| 🏷️ اسم یکدست همه کانفیگ‌ها (SS44-xxx) | ✅ | ❌ |
| 📊 آمار شفاف هر آپدیت ([STATS.md](STATS.md)) | ✅ | ❌ |
| 🔄 آپدیت خودکار هر ۳۰ دقیقه | ✅ | ✅ |

## 🩺 وصل نشد؟ اول این ۶ تا رو چک کن (۹۰٪ مشکل همین‌جاست)

1. **ساعت گوشی** باید روی Automatic باشد — ساعت اشتباه = همه کانفیگ‌های TLS/Reality fail میشن!
2. سابسکریپشن رو **Update** کن (کانفیگ دیشب امروز مرده) بعد `⋮ → Test all` بگیر
3. **اول GOLD** (`SS44-gold.txt`) رو امتحان کن — اینا هندشیک واقعی TLS رو پاس کردن
4. اگه VLESSها هیچ‌کدوم نخوردن، برو سراغ **`SS44-udp.txt`** (Hysteria2/TUIC با UDP کار می‌کنن و خیلی وقت‌ها وقتی TCP قفله رد میشن)
5. Fragment رو یک بار روشن / یک بار خاموش تست کن (Settings → Fragment)
6. یه بار **Hiddify** رو هم امتحان کن — گاهی همون کانفیگ تو یه اپ دیگه وصل میشه

> اگه حتی GOLD هم نخورد، مشکل تقریباً قطعاً سمت گوشی/اپراتوره (نه کانفیگ) — خطای دقیق برنامه رو بفرست تا بگم چشه.

## 🇮🇷 تنظیم حیاتی ایرانسل (مهم!)

اگر با اینترنت ایرانسل وصل نشدی:

1. در **v2rayNG** برو به `Settings → Fragment` و روشنش کن
2. دکمه `⋮ → Test all` را بزن و بر اساس پینگ سورت کن — Realityهای بالای لیست بالاترین شانس را دارند
3. اگر باز وصل نشد، یک بار Fragment روشن و یک بار خاموش تست کن

## ❓ سوالات پرتکرار

**یه کانفیگ تکی که ۱ ماه کار کنه نداره؟**
نه — هیچ ساب رایگانی چنین چیزی ندارد، چون کانفیگ‌های عمومی معمولاً بعد چند ساعت می‌میرند. راه درست همین سابسکریپشن است که هر ۳۰ دقیقه خودش را تازه می‌کند.

**آیا کانفیگ‌های رایگان امن‌اند؟**
برای کارهای حساس (بانک، ایمیل اصلی) نه. ترافیک از سرورهای ناشناس رد می‌شود. برای امنیت واقعی سرور شخصی بگیر.

**چطور به منابع اضافه کنم؟**
لینک ساب جدید را در لیست `SOURCES` داخل `fetch_test.py` بگذار.

---

## 🤖 موتور چطور کار می‌کند؟ | How it works

```
fetch (4 subs) → decode vmess → drop private/loopback IPs → dedupe by endpoint
→ TCP ping (500 max, 50 threads) → rank: reality ➜ :443 ➜ tls
→ rename SS44-xxx → publish txt + base64 + clash.yaml + STATS.md
```

- ⏱️ اجرا: هر ۳۰ دقیقه با GitHub Actions (`.github/workflows/update.yml`)
- 🖥️ اجرای دستی: `python3 fetch_test.py` (فقط پایتون خالص، بدون نیاز به نصب هیچ چیز)

## 📄 لایسنس

MIT — آزاد استفاده کن، فقط سورس را ذکر کن.
