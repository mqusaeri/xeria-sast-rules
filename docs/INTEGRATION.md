# Kontrak integrasi paket revisi

Penggunaan XERIA telah dikonfirmasi hanya internal. Tidak ada publikasi, push, atau deploy aplikasi yang dilakukan oleh perubahan repository ini.

## Pemilihan versi dan manifest

- Ambil empat paket pada `release-index.json`; verifikasi SHA-256 sebelum instalasi.
- Format manifest tetap schema 1 dengan `id`, `kind`, `format`, `version`, `source`, dan `files`.
- Versi Gitleaks `8.30.1.1` adalah versi paket, bukan versi binary. Semgrep juga telah memakai format versi empat komponen. Dukungan versi empat komponen pada importer Gitleaks XERIA perlu dikonfirmasi dengan aplikasi; jangan menganggap kompatibilitas sudah diuji.
- XERIA 0.10.6 memakai baseline 0.10.4 dan tidak mengimpor sanitizer JDBC ResultSet dari ZIP 0.10.5 yang sebelumnya tersarang. Tidak ada paket ZIP tersarang pada rilis baru.
- Payload yang tidak tercantum pada manifest, hash salah, YAML invalid/duplicate key atau error engine harus membuat status scan incomplete terlihat.

## ID dan suppression

ID source dipertahankan. Folder/filename ikut menentukan identitas; ID mentah saja tidak cukup. Exporter opsional membuat 1.741 ID code-rule unik dan index sumber. Jika platform mempertahankan ID native, uji kelompok ID berulang pada C# SSRF dan Terraform FSx secara khusus; penerimaan YAML bukan bukti seluruh mapping UI/database benar.

`suppress: []` adalah konfigurasi aktif. Riwayat 31 suppression di `docs/suppression-review.json` tidak ikut paket produksi. Tidak ada klaim bahwa platform saat ini mengaktifkan atau gagal memuat suppression lama; kode loader belum tersedia. Jika pengecualian tertentu diperlukan, buat scope proyek/file yang sempit, owner, alasan, expiry dan positive regression setelah format loader terverifikasi.

## Gating dan hasil

- Jangan menyamakan `ERROR` dengan critical atau `confidence: HIGH` dengan precision yang diukur.
- Rule baru yang mendeteksi konfigurasi trust secara eksplisit menggunakan kategori audit. Tiga rule boolean fail-open juga audit: nilai True mungkin berarti error dalam kontrak aplikasi, sehingga caller harus ditinjau.
- `openai-missing-moderation` mempertahankan ID, tetapi sekarang mencari hasil moderation yang dibuang. Ini perubahan semantik yang disengaja; keberadaan moderation dalam fungsi atau lokasi global tidak membuktikan enforcement.
- Rule UI/mobile yang sah tidak lagi diklaim exploit; beberapa tetap informational untuk review.
- Parse error, timeout, file yang dilewati, extractor failure, dan kedalaman arsip harus dilaporkan bersama hasil. Tidak ada finding tidak berarti semua file diperiksa.
- Re-run fixture melalui XERIA untuk memverifikasi extractor Blade/Vue/TS/embedded script, `xeria-syarat-berkas`, namespace, severity mapping, redaction, dedup, history scanning, dan fitur intrafile/interfile. Pengujian lokal hanya menjalankan engine dan konfigurasi paket.

## Batas yang tetap ada

Perbaikan ini bukan implementasi seluruh roadmap riset. Authorization bisnis/tenant, RAG ACL, wrapper khusus aplikasi, full cross-file/persistence dataflow, DNS rebinding/egress, GraphQL resource abuse, dan kualitas runtime guard memerlukan model atau integration test tambahan. Corpus proyek internal berlabel diperlukan untuk mengukur precision/recall dan noise; regression sintetis tidak memberikan skor akurasi global.
