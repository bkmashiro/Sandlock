# Sandlock 🔒

軽量なLinuxユーザースペースサンドボックス。root不要。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml)
[![Security Tests](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml)

**[English](README.md)** | **[中文](README_zh.md)**

## 機能

- 🔒 **seccomp-bpf** システムコールフィルタリング（60+の危険なコールをブロック）
- 📊 **リソース制限** - CPU、メモリ、ファイルサイズ、オープンファイル数
- 🌐 **ネットワーク分離** - すべてのソケット操作をブロック
- 🧵 **スレッドセーフ** - forkをブロックしつつスレッドは許可
- 🏔️ **Landlock** - ファイルシステムサンドボックス（カーネル5.13+）
- 🎯 **Strictモード** - パスレベルのシステムコール傍受（カーネル5.0+）
- ⚡ **低オーバーヘッド** - 約1.5msの起動コスト
- 🔧 **設定可能** - 各セキュリティ機能を個別に有効/無効
- 🚫 **root不要** - 純粋なユーザースペース実装

## 攻撃防御マトリックス

### 環境別の防御状況

| 攻撃 | Userspace | Lambda+Py | Lambda+Node | Lambda+Preload | Lambda単体 |
|------|:---------:|:---------:|:-----------:|:--------------:|:----------:|
| ネットワーク流出 | ✅ | ✅ | ✅ | ✅ | ❌ |
| リバースシェル | ✅ | ✅ | ✅ | ✅ | ❌ |
| Fork爆弾 | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| サブプロセス/exec | ✅ | ✅ | ✅ | ✅ | ❌ |
| メモリ枯渇 | ✅ | ✅ | ✅ | ✅ | ✅ |
| CPU枯渇 | ✅ | ✅ | ✅ | ✅ | ✅ |
| ディスク枯渇 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 無限ループ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 機密ファイル読取 | ✅ | ✅ | ✅ | ✅ | ❌ |
| /tmp外への書込 | ✅ | ✅ | ✅ | ✅ | ✅ |
| ptraceデバッグ | ✅ | ✅ | ✅ | ✅ | ✅ |
| シンボリックリンク | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| dlopen/FFI | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| eval/exec | N/A | ✅ | ✅ | N/A | ❌ |
| 直接syscall | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| サンドボックス脱出 | ✅ | ⚠️ | ⚠️ | N/A | N/A |
| /proc漏洩 | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| VPC水平移動 | N/A | ❌ | ❌ | ❌ | ❌ |
| IAM認証情報窃取 | N/A | ❌ | ❌ | ❌ | ❌ |

凡例: ✅ 防御済 | ⚠️ 部分的 | ❌ 未防御 | N/A 該当なし

**Lambda+Preload** = LD_PRELOAD + ソースコードスキャナー + 動的リンク（C/C++/Rust/Go用）

### 防御技術

| 攻撃 | Userspace | Lambda+Py/Node | Lambda+Preload | Lambda単体 |
|------|-----------|----------------|----------------|------------|
| ネットワーク | seccomp | import/モジュールブロック | LD_PRELOAD | ❌ VPC使用 |
| Fork | seccomp | import/モジュールブロック | LD_PRELOAD | Lambda制限 |
| メモリ | rlimit | rlimit | rlimit | Lambda設定 |
| CPU/タイムアウト | rlimit | rlimit | rlimit | Lambdaタイムアウト |
| ディスク | rlimit | rlimit | rlimit | /tmp 512MB |
| ファイル読取 | Landlock/strict | restricted open() | LD_PRELOAD | ❌ |
| ファイル書込 | Landlock/strict | restricted open() | LD_PRELOAD | 読取専用rootfs |
| ptrace | seccomp | ctypes/ffi無し | Firecracker | Firecracker |
| シンボリックリンク | seccomp | osモジュール無し | ⚠️ 部分的 | ❌ |
| FFI/dlopen | seccomp | importブロック | ソーススキャナー | ❌ |
| 直接syscall | seccomp | ⚠️ スキャナー | ⚠️ スキャナー | ❌ |
| サンドボックス脱出 | seccomp | ⚠️ 部分的 | N/A | N/A |

### Lambda内蔵保護

| 保護 | 説明 |
|------|------|
| ✅ 読取専用rootfs | /var/task, /optへの書込不可 |
| ✅ Firecracker seccomp | ptrace, mount, reboot等をブロック |
| ✅ メモリ制限 | 関数ごとに設定 (128MB-10GB) |
| ✅ タイムアウト | 関数ごとに設定 (最大15分) |
| ✅ /tmp制限 | 512MBエフェメラルストレージ |
| ❌ ネットワーク | デフォルトで完全な外向きアクセス |
| ❌ ファイル読取 | /etc/passwd, /proc等を読取可能 |
| ❌ サブプロセス | プロセス生成可能 |

### フルスタック比較: Lambda vs Userspace

**フルスタックUserspace:**
```
seccomp-bpf + Landlock + rlimits + 言語サンドボックス + ソーススキャナー + clean-env
```

**フルスタックLambda:**
```
VPC分離 + rlimits + 言語サンドボックス + LD_PRELOAD + ソーススキャナー + clean-env
```

| 攻撃 | フルスタックUserspace | フルスタックLambda | 回避難易度 |
|------|:--------------------:|:-----------------:|:----------:|
| ネットワーク流出 | ✅ seccomp+lang | ✅ VPC+lang+preload | 🔴 不可能 |
| リバースシェル | ✅ seccomp+lang | ✅ VPC+lang+preload | 🔴 不可能 |
| Fork/サブプロセス | ✅ seccomp+lang | ✅ lang+preload | 🔴 非常に困難 |
| メモリ/CPU/ディスク | ✅ rlimit | ✅ rlimit+Lambda | 🔴 不可能 |
| 機密ファイル読取 | ✅ Landlock+lang | ✅ lang+preload | 🔴 非常に困難 |
| /tmp外への書込 | ✅ Landlock | ✅ Lambda rootfs | 🔴 不可能 |
| ptrace | ✅ seccomp | ✅ Firecracker | 🔴 不可能 |
| 直接syscall | ✅ seccomp | ⚠️ スキャナーのみ | 🟡 困難 |
| dlopen/FFI | ✅ seccomp+lang | ✅ lang+scanner | 🔴 非常に困難 |
| サンドボックス脱出 | ✅ seccomp | ⚠️ lang+scanner | 🟡 困難 |
| /proc漏洩 | ⚠️ 部分的 | ⚠️ 部分的 | 🟢 中程度 |
| VPC水平移動 | N/A | ✅ VPC分離 | 🔴 不可能 |
| カーネル0day | ⚠️ | ⚠️ | 🔴 0day必要 |

**セキュリティレベル:**

| 構成 | セキュリティ | 用途 |
|------|:----------:|------|
| フルスタックUserspace | 🟢🟢🟢 | 最高セキュリティ、任意の信頼できないコード |
| フルスタックLambda | 🟢🟢 | 本番環境の学生コード実行 |
| Lambda + 言語サンドボックス | 🟡 | 基本的な保護 |
| Lambda単体 | 🟠 | 信頼できないコードには非推奨 |

## 言語サンドボックス

### Python サンドボックス

```bash
python lang/python/sandbox.py user_code.py --timeout 5 --memory 128
```

**ブロック:** `socket`, `subprocess`, `os`, `ctypes`, `mmap`, `pickle`
**許可:** `math`, `json`, `re`, `collections`, `datetime`

### JavaScript サンドボックス

```bash
# VM分離（より強力、API制限あり）
node lang/javascript/sandbox.js user_code.js --timeout 5000

# ランタイムラッパー（フルNode API、モジュールブロック）
node lang/javascript/wrapper.js user_code.js
```

### ソースコードスキャナー

```bash
python lang/scanner/scanner.py code.c --json
```

**検出:** `asm()`, `syscall`, `int 0x80`, `_start()`, `ctypes`, `dlopen`

### LD_PRELOAD フック

```bash
cd lang/preload && make

LD_PRELOAD=./sandbox_preload.so \
  SANDBOX_NO_NETWORK=1 \
  SANDBOX_NO_FORK=1 \
  ./user_program
```

⚠️ インラインアセンブリで回避可能。ソーススキャナーと併用すること。

## クイックスタート

```bash
# ビルド
make

# ネットワークをブロック
./sandlock --no-network -- curl https://evil.com

# リソース制限
./sandlock --cpu 5 --mem 64 -- python3 heavy_script.py

# フルサンドボックス
./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- ./untrusted
```

## インストール

```bash
# ソースからビルド（libseccomp-dev必要）
sudo apt install libseccomp-dev
make
sudo make install
```

## ライセンス

MIT License - [LICENSE](LICENSE)参照
