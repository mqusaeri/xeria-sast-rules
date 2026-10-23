# Audit dan roadmap rule XERIA

Tanggal acuan ancaman: **23 Oktober 2026**. XERIA digunakan **hanya untuk internal**.
Dokumen ini membedakan temuan pada paket awal, perbaikan yang sudah diterapkan, dan pekerjaan lanjutan.
Daftar perubahan definitif ada di [PATCHES.json](../PATCHES.json); hasil pemeriksaan rilis ada di [VALIDATION.json](../VALIDATION.json).
Lihat juga [CHANGELOG.md](../CHANGELOG.md) dan [panduan integrasi](INTEGRATION.md).

## Baseline dan hasil perubahan

Baseline audit adalah commit `246a7c825ad37c58b99dda74cb60a500887d3318`, berisi empat ZIP utama.
Jumlah di bawah menghitung entri rule dengan identitas paket/path/ID, bukan jumlah bahasa atau jumlah file.

| Paket | Baseline | Rule lama diubah | Rule ditambah | Rule dihapus | Sesudah perubahan |
|---|---:|---:|---:|---:|---:|
| Semgrep | 1.462 | 24 | 0 | 0 | 1.462 |
| MobSF | 103 | 18 | 0 | 0 | 103 |
| Gitleaks | 222 | 1 | 0 | 0 | 222 |
| Custom XERIA | 167 | 31 | 9 | 0 | 176 |
| **Total** | **1.954** | **74** | **9** | **0** | **1.963** |

Perbaikan konfigurasi global, seperti allowlist Gitleaks, dicatat terpisah dari jumlah rule yang berubah.
ZIP XERIA 0.10.5 yang tersarang di ZIP lama tidak dihitung dua kali karena memuat ID yang sama.
Gunakan [release-index.json](../release-index.json) untuk memilih empat paket aktif; ZIP lama tersedia pada commit baseline di riwayat Git.
Perubahan ini tidak berarti seluruh roadmap, integrasi platform, atau pengukuran akurasi produksi sudah selesai.

## Bukti audit awal dan tindak lanjut

Audit awal menginventarisasi seluruh entri rule dan melakukan tinjauan semantik serta pengujian perilaku terarah.
Seluruh 1.446 YAML Semgrep, 51 YAML MobSF, dan TOML Gitleaks cocok dengan sumber upstream yang dinyatakan.
Karena itu kelemahan upstream tetap perlu diuji ulang pada engine dan konfigurasi internal XERIA.

| Temuan pada baseline | Perubahan dalam revisi ini |
|---|---|
| Suppression YAML mengandung U+0008; ZIP baru tersarang tanpa terdaftar pada manifest luar | Paket dibangun dari source yang dapat ditinjau; manifest/inventaris payload divalidasi; nesting tak dinyatakan ditolak |
| Berkas mendeklarasikan 31 suppression global berdasarkan sampel proyek terbatas | Daftar aktif dikosongkan; alasan historis disimpan untuk review. Dampak kenaikan finding perlu diukur pada aplikasi internal |
| Parsing URL, HTML escaping, validator yang tidak digunakan, atau hash tak dibandingkan dianggap cukup mengamankan input | Sanitizer/guard terpilih diperbaiki; counterexample dijadikan regression fixture bersama contoh aman |
| Alias filter MongoDB, nama variabel ZIP, dan metavariable tak terikat menyebabkan pola terlewat | Model sink/metavariable diperbaiki tanpa menghapus ID lama |
| JWT verification dalam cabang mati, ekspresi CI boolean, dan OIDC subject terlalu luas menutupi risiko | Pola terkait diperbaiki dan diuji terhadap varian aman serta berisiko |
| Global allowlist secret mencocokkan substring `false`; keyword provider dapat menghalangi deteksi | Anchoring allowlist diperbaiki; rule provider terkait diperluas; tersedia profil pemeriksaan secret mendalam yang eksplisit |
| RNG sistem Swift, TLS default Java, query terparameterisasi, dan UI biasa menghasilkan alarm berlebihan | Pola dan klasifikasi mobile ditinjau; penggunaan API biasa tidak otomatis dianggap vulnerability |
| MCP memakai parsing URL/escaping HTML sebagai sanitizer; sumber LLM modern belum dimodelkan | HTTP client dan Responses API diperluas; trust-boundary MCP diberi klasifikasi review yang sesuai |
| Autofix Django salah memahami return value validasi password | Autofix yang tidak aman dihapus; rule deteksi dipertahankan. Perubahan auth/crypto memerlukan pengujian perilaku sebelum auto-apply |

Temuan historis di atas bukan pernyataan bahwa revisi saat ini masih gagal pada counterexample yang sama.
Sebaliknya, lulusnya fixture terpilih tidak membuktikan semua bentuk program atau seluruh pipeline XERIA sudah tercakup.
Asumsi “data dari DB/API internal pasti aman” tetap harus dihindari: input berbahaya dapat tersimpan lalu dipakai kembali.

## Sembilan rule baru dan batas kesimpulannya

- XSS PHP pada atribut HTML tanpa quote, termasuk ketika nilai hanya diberi HTML encoding.
- PyTorch `weights_only=False` dan Transformers `trust_remote_code=True` yang secara eksplisit membuka trust terhadap artefak/kode model.
- PyJWT yang secara eksplisit menonaktifkan pemeriksaan audience atau issuer.
- Review hasil boolean setelah kegagalan verifikasi PyJWT, jsonwebtoken Node, atau signature webhook Stripe.
- Review ekstraksi tar yang secara eksplisit memakai filter `fully_trusted`.

Sembilan rule baru diklasifikasikan sebagai **audit/review**; konfigurasi trust yang eksplisit tidak selalu merupakan kerentanan.
Tiga rule exception/boolean belum mengikat nilai return ke keputusan akses pemanggil: `true` juga dapat berarti indikator error.
Validasi eksternal, artefak tepercaya, atau penggunaan inspeksi dapat menjadi konteks sah yang harus diperiksa.
Rule tersebut tidak mengklaim cakupan lengkap tenant authorization, RAG, OAuth, atau semua wrapper lintas file.

## Dasar ancaman global hingga tanggal acuan

Snapshot resmi [CISA KEV](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json) yang diakses saat audit menyatakan versi **2026.10.21** dan **1.754 entri**.
Sebanyak **270 entri** ditambahkan selama 2026 hingga snapshot tersebut; publikasinya belum mencakup kepastian kejadian 22–23 Oktober.
Di kelompok penambahan itu terdapat CWE-94 code injection (19), CWE-287 authentication (17), CWE-78 command injection (15), CWE-22 traversal (14), CWE-502 deserialization (13), CWE-306 missing authentication (12), dan CWE-918 SSRF (11).
Angka ini menghitung **entri CVE katalog**, bukan jumlah serangan, korban, atau prevalensi global; satu entri dapat memiliki beberapa CWE.
Data ini mendukung prioritas boundary trust, autentikasi, injection, file/archive dan tujuan jaringan sesuai aset internal.

Sumber resmi tambahan yang dibaca:

- [OWASP Top 10:2025](https://github.com/OWASP/Top10/blob/master/2025/docs/en/index.md): access control, software supply chain, authentication, dan mishandling of exceptional conditions.
- [OWASP API Security 2023](https://github.com/OWASP/API-Security/blob/master/editions/2023/en/0x11-t10.md): object/property/function authorization, resource consumption, SSRF dan konsumsi API tidak aman.
- [OWASP LLM Top 10:2025](https://genai.owasp.org/llm-top-10/): improper output handling, excessive agency, retrieval/vector isolation, supply chain dan disclosure.
- [OWASP Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/): halaman resmi bertanggal 9 Desember 2025 tentang boundary sistem agentic.
- [OWASP GenAI Red Teaming Manual v1.0](https://genai.owasp.org/resource/genai-red-teaming-manual-version-1-0/): halaman resmi 20 Oktober 2026, menekankan pengujian runtime dan temuan yang dapat direproduksi.
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use): input tidak tepercaya, minimum permissions dan pinning dependensi workflow.

Halaman OWASP Top 10/API utama mengembalikan 403; audit membaca repositori GitHub resmi yang ditautkan di atas.
PDF Agentic 2026 beralih ke halaman tanpa akses, sehingga isi lengkap PDF itu tidak diklaim telah dibaca.
URL sumber dapat berubah setelah audit; tanggal feed yang dilaporkan merupakan snapshot sesi audit, bukan sifat permanen URL.

## Roadmap yang masih memerlukan konteks aplikasi internal

Rule SSRF, JWT, CI, AI/MCP dan mobile sudah tersedia; pekerjaan berikut memperdalam model dan kualitas, bukan menganggap cakupan saat ini nol.
Absensi nama model khusus tidak membuktikan semua contoh di area itu pasti lolos karena rule generik dapat membantu.

| Tahap | Area | Konteks yang diperlukan | Kriteria penerimaan berikutnya |
|---|---|---|---|
| 1 — Integrasi dan baseline | Loader, ID, suppression, extraction/template, ignore, archive, redaction | Konfigurasi XERIA dan versi engine produksi | Fixture yang sama dijalankan lewat pipeline XERIA; selisih dijelaskan; parse/error/timeout/skip terlihat |
| 1 — Noise dan gating | Severity, dedup dan suppression per proyek | Corpus aman/rentan berlabel dari aplikasi internal | Precision/recall per keluarga dan framework; scope/owner/expiry pada pengecualian; rollback rilis tersedia |
| 2 — Authorization | BOLA/IDOR dan tenant scope | Model data, ORM, endpoint, global guard/policy dan makna role | Lookup/update/delete lintas tenant teruji; scoped query dan guard sah menjadi negatif; uji dua user/tenant |
| 2 — Framework | Source input modern, typed body, server actions, async/helper | Dua–tiga stack dominan dan versi library | Alias/wrapper/async teruji; sumber menuju sink aktual; tidak hanya mendeteksi nama framework |
| 2 — Second-order | DB/API/queue/cache/file tersimpan menuju HTML/SQL/shell | Jalur ingest, penyimpanan dan konsumsi data | Kontrol encoding/binding konteks benar; persistence flow diuji melalui integrasi; batas interfile dijelaskan |
| 2 — CI artifact trust | Artifact/cache/reusable workflow menuju job berprivilege | Workflow internal, permissions, provenance dan trust OIDC | Untrusted artifact-to-execution positif; pin/provenance/trust sempit negatif; secret exposure ditangani |
| 3 — RAG dan agent | Retrieval tenant isolation dan authorization tool | Vector DB, filter server-side, registry tool, identitas agent dan izin | User tidak bisa mengganti scope tenant; output tak dipercaya tidak otomatis mengizinkan tool; runtime abuse tests |
| 3 — Mobile | Intent, deep-link, PendingIntent dan hybrid bridge | Manifest, build type, SDK Android/iOS dan WebView/bridge aktual | Sumber Intent/URL menuju aksi sensitif; origin/component validation negatif; release/debug dibedakan |
| 3 — GraphQL/API | Resolver authorization, depth/cost/batching, webhook replay | Schema resolver, middleware, provider dan raw-body processing | Guard dan limit yang dinonaktifkan teruji; konfigurasi sah negatif; replay dan cross-user test runtime |

Tahap dapat berjalan paralel setelah dependensinya tersedia. Daftar ini bukan janji seluruh keluarga selesai dalam satu rilis.
Pengujian atas kegagalan yang sudah ditemukan tetap dipertahankan ketika model baru ditambahkan.

## Pengukuran dan pemeliharaan

1. Hubungkan threat → CWE/API → framework → source/sink/guard → rule → fixture → engine/version.
2. Untuk perubahan rule, gunakan positif, negatif aman, alias/helper/async yang relevan, serta sanitizer near-miss; nilai expected finding dan lokasi.
3. Simpan provenance/license notice, diff upstream, hasil regression, konfigurasi scan, skipped coverage dan known limitations pada rilis.
4. Tinjau KEV/advisory/SDK drift berkala; pilih apakah mitigasi membutuhkan SAST, SCA/SBOM, IaC, secret scanning, DAST atau runtime policy.
5. Ukur precision/recall pada holdout berlabel yang tidak dipakai menulis rule; jumlah rule dan jumlah fixture lulus bukan skor akurasi global.

SAST tidak menjamin ketiadaan phishing, credential theft runtime, vendor compromise, DNS rebinding, model poisoning atau authorization lintas layanan.
Status pemeriksaan yang benar-benar dijalankan harus terlihat; keberhasilan instalasi atau fixture lokal tidak membuktikan kesiapan semua integrasi produksi.
