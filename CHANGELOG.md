# Perbaikan rule — 23 Oktober 2026

Rilis lokal untuk XERIA internal: **74 rule lama diubah, 9 rule baru ditambahkan, 0 rule dihapus**. Total naik dari **1.954 menjadi 1.963**. Perhitungan membandingkan definisi rule terhadap empat ZIP pada commit baseline yang dipin dalam `release-config.json`; perubahan komentar atau konfigurasi global tidak dihitung sebagai rule tambahan.

| Paket | Versi baru | Awal | Diubah | Ditambah | Dihapus | Akhir |
|---|---|---:|---:|---:|---:|---:|
| XERIA custom | 0.10.6 | 167 | 31 | 9 | 0 | 176 |
| Semgrep + patch XERIA | 2026.10.23.1 | 1462 | 24 | 0 | 0 | 1462 |
| MobSF + patch XERIA | 1.0.1 | 103 | 18 | 0 | 0 | 103 |
| Gitleaks + patch XERIA | 8.30.1.1 | 222 | 1 | 0 | 0 | 222 |

## Rule lama yang diperbaiki

- **XERIA custom (31):** sanitizer XSS/SQL/redirect yang terlalu luas; guard origin/hash/value yang tidak terkait atau mencakup cabang salah; NoSQL melalui alias; literal credential; scope API deserialisasi; upload; CORS; dan konfigurasi Compose/Traefik. Metadata membedakan audit dari kerentanan yang telah dibuktikan.
- **Semgrep (24):** SSRF Go/MCP, JWT/CI/OIDC, pemanggilan ECB dan Go ZIP, validasi password Django, konfigurasi cooldown npm/uv, Responses API/tool arguments, serta metadata/pola AI. Autofix Django/crypto yang tidak aman dihapus, sementara rule deteksi dipertahankan.
- **MobSF (18):** shell argument array, properti TLS Swift, RNG sistem, SSLContext, parameter SQL, XXE, clipboard, dan klasifikasi UI/TLS/CBC.
- **Gitleaks (1 + konfigurasi global):** keyword Airtable diperbaiki; allowlist boolean/null diberi grouping dan anchoring yang benar. Total provider rule tetap 222.

Daftar ID, field yang berubah, dan hash file terdapat pada [PATCHES.json](PATCHES.json). “Diubah” mencakup pola deteksi, metadata, pesan, severity, atau autofix; angka 74 tidak berarti semuanya memperoleh peningkatan recall terukur.

## Sembilan rule baru — semuanya di XERIA custom

| ID | Fokus |
|---|---|
| `php-html-encoding-in-unquoted-attribute` | Input request yang telah di-encode HTML tetapi masuk ke atribut tanpa tanda kutip. |
| `xeria-node-jwt-verification-fail-open` | Exception verifikasi Node jsonwebtoken diikuti return true. |
| `xeria-pyjwt-audience-check-disabled` | PyJWT dengan pemeriksaan audience dimatikan. |
| `xeria-pyjwt-verification-fail-open` | Exception verifikasi PyJWT diikuti return True. |
| `xeria-pyjwt-issuer-check-disabled` | PyJWT dengan pemeriksaan issuer dimatikan. |
| `xeria-pytorch-unsafe-pickle-load` | Pemanggilan PyTorch dengan weights_only=False secara eksplisit. |
| `xeria-stripe-webhook-verification-fail-open` | Exception verifikasi webhook Stripe diikuti return True. |
| `xeria-tarfile-fully-trusted-extraction` | Ekstraksi tar dengan filter fully_trusted secara eksplisit. |
| `xeria-transformers-remote-code-trust` | Transformers dengan trust_remote_code=True secara eksplisit. |

Rule baru dikategorikan audit dengan batas deteksi pada metadata. Tiga pola fail-open perlu meninjau kontrak caller: return True belum membuktikan bahwa otorisasi diberikan. Penerimaan artifact, version library, dan trust boundary tetap menentukan risiko.

## Perubahan paket dan proses

- Source dapat ditinjau di `packs/`, regression di `tests/`, serta build/installer ber-checksum di `scripts/`. ZIP, manifest, dan release index dibuat deterministik; semua payload harus terdaftar dan cocok hash/ukurannya.
- Suppression aktif menjadi `suppress: []`; 31 entri lama dipindah ke [catatan review](docs/suppression-review.json). Efek suppression lama di platform belum diketahui karena loader produksi tidak tersedia.
- ZIP 0.10.5 yang sebelumnya tersarang tidak dibawa ke rilis baru. Sanitizer JDBC ResultSet di versi tersarang itu tidak diimpor.
- Exporter namespace opsional menyediakan ID eksplisit pack + path + ID asal untuk 1.741 code rules. ID pada paket source dipertahankan.
- Profile Gitleaks mendalam membuka pengecualian path tertentu secara eksplisit; default upstream tetap menjadi baseline. Archive depth merupakan opsi runtime.
- Workflow CI disediakan. Hasil lokal tercatat di [VALIDATION.json](VALIDATION.json); belum ada klaim GitHub Actions atau aplikasi XERIA telah menjalankannya.

## Validasi dan pekerjaan selanjutnya

Seluruh 356 assertion regression lulus: 355 target dipindai dan satu pengecualian path diuji secara eksplisit. Sebanyak 26 unit/integration tests lokal lulus tanpa skip; peer review independen mengulang 23 kasus dan kontrol aman. Smoke gabungan memuat 1.741 code rules dan menjalankan 675 rule relevan pada tiga target, tanpa error. Angka ini bukan pengukuran precision/recall pada aplikasi internal.

Lihat [audit dan roadmap](docs/AUDIT-AND-ROADMAP.md) untuk pekerjaan authz tenant, framework, persistence, RAG, dan runtime yang masih terbuka. [Kontrak integrasi](docs/INTEGRATION.md) menjelaskan pemeriksaan versi engine, importer, suppression, namespace, extractor, dan severity yang masih membutuhkan aplikasi XERIA.
