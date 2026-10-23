# XERIA SAST rule packs

Paket rule untuk pemakaian internal XERIA. Source yang bisa ditinjau ada di `packs/`; ZIP di root dibuat secara deterministik dari source tersebut. `release-index.json` adalah daftar empat paket rilis aktif beserta SHA-256 dan jumlah rule.

| Paket | Versi paket baru | Jumlah rule |
|---|---|---:|
| XERIA | 0.10.6 | 176 |
| Semgrep rules + patch XERIA | 2026.10.23.1 | 1.462 |
| MobSF rules + patch XERIA | 1.0.1 | 103 |
| Gitleaks rules + patch XERIA | 8.30.1.1 | 222 |
| **Total** | | **1.963** |

Versi paket Gitleaks `8.30.1.1` adalah revisi rule lokal; binary penguji tetap Gitleaks `8.30.1`. OpenGrep penguji dipin pada `1.29.0`. Nomor versi engine fork tidak dibandingkan secara leksikal dengan Semgrep.

## Menyiapkan dan menguji

Python 3.12+, Linux x86_64 untuk installer engine bawaan:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/install_tools.py
export OPENGREP_BIN="$PWD/.build/tools/opengrep"
export GITLEAKS_BIN="$PWD/.build/tools/gitleaks"
export XDG_CACHE_HOME="$PWD/.build/cache"
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/test_rules.py --jobs 2
.venv/bin/python scripts/smoke_engine.py
.venv/bin/python scripts/build_packs.py --check
```

Installer memeriksa TLS dan SHA-256 yang dipin. Semua dependency/cache/hasil engine berada di `.venv/` dan `.build/`, diabaikan Git. Pada platform lain, sediakan kedua binary terverifikasi melalui variabel di atas. Tidak ada credential yang diperlukan untuk fixture lokal.

Pengujian rule memeriksa ID, nomor baris, jumlah finding, target benar-benar dipindai, exit status, error engine, dan versi aktual. Kasus pengecualian path harus menyatakan `expect_scanned: false` serta alasan secara eksplisit; hasilnya dicatat sebagai assertion pengecualian, bukan scan bersih. Fixture merupakan teks uji yang tidak dieksekusi sebagai aplikasi.

## Mengubah dan merilis

1. Edit source di `packs/<id>/`, bukan ZIP. Pertahankan ID atau sertakan migrasi yang jelas.
2. Tambahkan positive/negative regression pada `tests/regression/*.json`; jalankan suite relevan, lalu suite gabungan dan unit tests.
3. Ubah versi paket dan tanggal di `release-config.json`. Pertahankan `source.revision` upstream; patch lokal dicatat terpisah.
4. Jalankan `.venv/bin/python scripts/update_patch_ledger.py` untuk membuat `PATCHES.json` terhadap commit baseline yang dipin. Command ini memerlukan objek commit tersebut di Git lokal; checkout shallow perlu mengambil riwayat yang relevan.
5. Jalankan `.venv/bin/python scripts/build_packs.py`, kemudian `--check`. Build menolak YAML duplicate-key, nested ZIP/manifest, dan symlink. Manifest menyebut seluruh payload, ukuran, dan SHA-256; ZIP reproducible mempunyai timestamp dan mode tetap.
6. Distribusikan hanya versi aktif pada `release-index.json`. Versi baseline tetap bisa diambil dari Git, sehingga tidak ada ZIP versi lama yang tercampur di daftar rilis aktif.

CI pada `.github/workflows/rules.yml` memeriksa bundle dan menjalankan test suite. Menambahkan workflow ke repository tidak membuktikan GitHub Actions telah berjalan; lihat `VALIDATION.json` untuk hasil lokal.

## Perubahan perilaku penting

- Perbaikan sanitizer/guard mengembalikan deteksi yang sebelumnya terlewat; sebagian finding baru pada aplikasi internal adalah konsekuensi yang diharapkan dan tetap perlu triage.
- Daftar suppression global kini kosong. Alasan 31 suppression lama disimpan untuk review pada `docs/suppression-review.json`; alasan itu tidak dimuat sebagai konfigurasi aktif. Jangan mengubah pengamatan satu proyek menjadi pengecualian global tanpa positive regression.
- Autofix yang mengubah semantik Django/ECB/math-rand secara tidak aman dihapus. Rule deteksinya tetap ada dan menyediakan pesan remediasi.
- Beberapa rule heuristic kini berstatus audit/INFO/WARNING dan confidence yang sesuai. Tinjau metadata, bukan hanya label ERROR/WARNING, saat menentukan blocking policy.
- Sembilan rule baru mencakup PyTorch/Transformers, konfigurasi trust PyJWT, fail-open JWT/Stripe, filter ekstraksi tar, dan encoding HTML pada atribut tanpa tanda kutip. Batas deteksi dinyatakan pada metadata; kecocokan pola tetap perlu diperiksa dalam konteks aplikasi.

## Profile secret mendalam

Default Gitleaks tetap mempertahankan pengecualian path upstream untuk mengendalikan noise. Profile tambahan membuka teks SVG, lockfile JS, dan `node_modules` untuk scan artefak yang memang memerlukannya:

```bash
.venv/bin/python scripts/gitleaks_profile.py
"$GITLEAKS_BIN" dir /path/to/authorized/source \
  --config .build/profiles/gitleaks-deep.toml \
  --max-archive-depth 1 --redact --no-banner
```

Archive depth, CPU/memory, total ukuran ekstraksi, dan proteksi ingest tetap menjadi tanggung jawab integrasi platform. Exit Gitleaks `1` berarti finding; bedakan dari error. Pengujian repository menggunakan token sintetis dan memeriksa redaction.

## Namespace dan integrasi

Bare ID upstream berulang pada beberapa file. Adapter opsional membuat config dengan ID eksplisit berisi pack, path file, dan ID asal:

```bash
.venv/bin/python scripts/export_engine_config.py
"$OPENGREP_BIN" scan --config .build/engine/rules.yaml \
  --no-rewrite-rule-ids /path/to/authorized/source
```

Index pemetaan ada di `.build/engine/rules.index.json`. Adapter ini tidak menggantikan postprocessing XERIA seperti `xeria-syarat-berkas`, extractor template, suppression scope, atau deduplikasi. Default namespace engine dan importer versi paket harus diuji pada aplikasi XERIA sebelum aktivasi. Source platform tidak ada dalam repository ini.

## Upstream dan bukti

Seluruh snapshot rule awal Semgrep/MobSF/Gitleaks cocok dengan sumber yang dinyatakan manifest. Setelah patch ini, paket memang berbeda dari upstream; `PATCHES.json` mencatat file/hash dan rule yang berubah, ditambah, atau dihapus. Notice dan lisensi setiap sumber dipertahankan.

Fixture upstream Semgrep dapat dipulihkan secara terpisah:

```bash
.venv/bin/python scripts/fetch_upstream_fixtures.py
```

Script mengambil snapshot ber-checksum, memulihkan 1.517 file fixture dan menyimpan index di `.build/upstream-fixtures/`. Ini **bukan** klaim 1.517 test sudah dijalankan atau lulus pada rule yang dipatch. Ekspektasi upstream lama perlu dibandingkan dengan perubahan semantik yang disengaja; suite regression lokal adalah gate rilis perubahan ini.

Lihat [changelog](CHANGELOG.md), [ledger perubahan](PATCHES.json), [hasil validasi](VALIDATION.json), [audit dan roadmap](docs/AUDIT-AND-ROADMAP.md), serta [kontrak integrasi](docs/INTEGRATION.md) untuk rincian dan batas validasi.
