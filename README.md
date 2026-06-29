# Email Verifier

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)

**Email Verifier Pro** adalah *tool* berbasis Python yang dirancang untuk melakukan validasi dan verifikasi email secara mendalam. *Tool* ini tidak hanya memeriksa format sintaksis email, tetapi juga memverifikasi apakah email tersebut benar-benar aktif dan dapat menerima pesan (bukan email palsu/kuantitas korporat), serta mengklasifikasikan apakah email tersebut milik pribadi (gratis/publik) atau perusahaan (*corporate/business email*).

---

## ✨ Fitur Utama

* **Deliverability Verification (SMTP Check):** Melakukan pengecekan langsung ke server mail (MX Record) untuk memastikan kotak masuk benar-benar ada dan dapat menerima email tanpa mengirimkan email sampah asli.
* **Syntax & Format Validation:** Memastikan email sesuai dengan standar RFC 5322.
* **Disposable/Temporary Email Detection:** Mendeteksi dan menyaring email palsu atau email sekali pakai (*burnable/disposable email*) seperti Mailinator, GuerrillaMail, dll.
* **Domain Classification:** Secara otomatis mengidentifikasi dan memisahkan kategori email:
    * **Personal/Public Email:** Layanan gratis seperti Gmail, Yahoo, Outlook, dll.
    * **Corporate/Business Email:** Email kustom menggunakan domain perusahaan (contoh: `nama@perusahaan.com`).
* **Catch-All Domain Detection:** Mendeteksi jika server tujuan dikonfigurasi untuk menerima semua email (*catch-all*), yang biasanya memengaruhi akurasi pengiriman.

---

## 🛠️ Arsitektur & Teknologi

* **Bahasa Pemrograman:** Python 3.8+
* **Library Utama:**
    * `dnspython`: Untuk query DNS dan validasi MX (Mail Exchange) Records.
    * `smtplib`: Untuk melakukan handshake SMTP tingkat rendah guna memeriksa keberadaan kotak masuk.
    * `re` (Regex): Untuk validasi sintaksis awal yang super cepat.

---

## 🚀 Cara Instalasi & Penggunaan

### 1. Klon Repositori
```bash
git clone [https://github.com/username/email-verifier-pro.git](https://github.com/username/email-verifier-pro.git)
cd email-verifier-pro
