# DEPLOY ONLINE — BUILD 74 (SUBDOMAIN GRATIS)

BUILD 74 disiapkan untuk Render. Render memberikan setiap Web Service sebuah subdomain `onrender.com`, sehingga domain berbayar belum diperlukan.

## 1. Buat akun Render
Buka https://render.com/ dan buat akun.

## 2. Upload kode
Cara termudah: buat repository GitHub baru dan upload seluruh isi folder BUILD 74 ke repository tersebut.

## 3. Buat Web Service
Di Render pilih **New → Web Service**, hubungkan repository, lalu pilih Docker.

Render akan memberikan alamat seperti:
`https://rsp-smart-clinic-xxxx.onrender.com`

## 4. Environment Variables
Isi:
- `ADMIN_USER` = admin
- `ADMIN_PASSWORD` = password Admin yang kuat
- `PUBLIC_BASE_URL` = alamat `https://...onrender.com` yang diberikan Render
- `RSP_BUILD` = 74
- `DB_FILE` = `/app/data/rsp_smart_clinic.db`

Jangan tambahkan slash `/` di akhir PUBLIC_BASE_URL.

## 5. Setelah deploy
Buka:
`https://ALAMAT-RENDER-ANDA.onrender.com/api/health`

Harus terlihat JSON dengan build `74`.

Lalu buka:
`https://ALAMAT-RENDER-ANDA.onrender.com/website/`

## 6. Pengaturan QR
Di Admin → Pengaturan, gunakan alamat Render HTTPS yang sama sebagai alamat publik verifikasi.

QR baru harus mengarah ke:
`https://ALAMAT-RENDER-ANDA.onrender.com/verify/TOKEN`

Scan QR menggunakan HP. HP tidak perlu berada di Wi-Fi yang sama.

## 7. Penting tentang Render Free
Free Web Service cocok untuk pengujian. Render menyatakan filesystem lokal pada Free Web Service tidak persisten. Karena aplikasi saat ini menggunakan SQLite, jangan menganggap database lokal Free sebagai penyimpanan produksi. Simpan backup dan nanti pindahkan database ke penyimpanan persisten sebelum dipakai sebagai sistem utama.
