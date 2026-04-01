🔧 Produced by OSSiqn — github.com/ossiqn
📜 License: MIT © 2024 OSSiqn — All rights reserved.

Bu araç OSSiqn tarafından InfoSec topluluğuna katkı amacıyla geliştirilmiştir.
This tool was developed by OSSiqn as a contribution to the global InfoSec community.[Markdown.md](https://github.com/user-attachments/files/26413808/Markdown.md)
Markdown

# 🔍 ScanLine - OSINT Security Scanner
### Developed & Maintained by OSSiqn
---

OSINT Security Scanner v1.0.0
Developed by OSSiqn Team

text


---

## 🇹🇷 Türkçe Açıklama

**ScanLine**, OSSiqn tarafından geliştirilen açık kaynaklı bir OSINT güvenlik tarama aracıdır.

### Ne Yapar?
- 🔎 **GitHub Code Search** üzerinde unutulmuş API anahtarlarını, şifreleri ve gizli bilgileri tarar
- 📋 **Pastebin** ve **GitHub Gist** üzerindeki veri sızıntılarını tespit eder
- 🔐 **SSL sertifika** geçerlilik kontrolü yapar
- 🛡️ **HTTP güvenlik başlıklarını** analiz eder
- 💬 Bulgularını **Discord** ve **Telegram** üzerinden anlık bildirir
- 🌐 **Canlı web arayüzü** ile tüm sonuçları şık bir terminal temalı panelde gösterir
- 🐳 **Docker** ile tek komutla kurulur

### Kimler Kullanabilir?
- Güvenlik araştırmacıları
- Penetrasyon test uzmanları
- Bug bounty avcıları
- Kurumsal güvenlik ekipleri

### ⚠️ Yasal Uyarı
Bu araç **yalnızca** kendi sistemlerinizde, izin verilmiş hedeflerde veya eğitim amaçlı kullanılmalıdır.
İzinsiz sistemlere erişim **Türk Ceza Kanunu 243-244. maddeleri** kapsamında suçtur.

---

## 🇬🇧 English Description

**ScanLine** is an open-source OSINT security scanning tool developed and maintained by **OSSiqn**.

### What Does It Do?
- 🔎 Scans **GitHub Code Search** for forgotten API keys, passwords, and sensitive credentials
- 📋 Detects data leaks on **Pastebin** and **GitHub Gists**
- 🔐 Validates **SSL certificate** expiry and integrity
- 🛡️ Analyzes **HTTP security headers** for misconfigurations
- 💬 Sends real-time alerts via **Discord** and **Telegram**
- 🌐 Displays all results in a beautiful **dark terminal-themed web dashboard**
- 🐳 **Docker-ready** — runs with a single command

### Who Is It For?
- Security researchers
- Penetration testers
- Bug bounty hunters
- Corporate security teams

### ⚠️ Legal Disclaimer
This tool must be used **only** on systems you own, have explicit permission to test,
or for educational purposes. Unauthorized access to computer systems is illegal worldwide.

---

## 🚀 Hızlı Kurulum / Quick Start

### Docker ile / With Docker
\`\`\`bash
git clone https://github.com/ossiqn/scanline
cd scanline
cp .env.example .env
nano .env
docker-compose up -d
\`\`\`

### Manuel / Manual
\`\`\`bash
pip install -r requirements.txt
python src/main.py
\`\`\`

### Web Arayüzü / Web Dashboard
\`\`\`
http://localhost:5000
\`\`\`

---

## ⚙️ Yapılandırma / Configuration

| Değişken / Variable | Açıklama / Description |
|---|---|
| `GITHUB_TOKEN` | GitHub Personal Access Token |
| `DISCORD_WEBHOOK_URL` | Discord webhook bildirimleri / notifications |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | Telegram chat/group ID |

---

## 📊 Özellikler / Features

| Özellik / Feature | Durum / Status |
|---|---|
| GitHub Code Scanning | ✅ Aktif / Active |
| Pastebin Monitoring | ✅ Aktif / Active |
| GitHub Gist Scanning | ✅ Aktif / Active |
| SSL Certificate Check | ✅ Aktif / Active |
| HTTP Header Analysis | ✅ Aktif / Active |
| Discord Notifications | ✅ Aktif / Active |
| Telegram Notifications | ✅ Aktif / Active |
| Web Dashboard | ✅ Aktif / Active |
| Docker Support | ✅ Aktif / Active |
| Shodan Integration | 🔄 Yakında / Coming Soon |
| Censys Integration | 🔄 Yakında / Coming Soon |

---

## 👥 Geliştirici / Developer

**OSSiqn Team**
- 🌐 GitHub: [@ossiqn](https://github.com/ossiqn)
- 📧 İletişim / Contact: ossiqn@proton.me

---

## 📜 Lisans / License

MIT License — © 2024 OSSiqn. All rights reserved.

---

*Bu araç OSSiqn tarafından InfoSec topluluğuna katkı amacıyla geliştirilmiştir.*
*This tool was developed by OSSiqn as a contribution to the InfoSec community.*
