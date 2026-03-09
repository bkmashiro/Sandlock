# Sandlock 🔒

Linux向け軽量ユーザースペースサンドボックス。root権限不要。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml)
[![Security Tests](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml)

**[English](README.md)** | **[中文](README_zh.md)**

## 特徴

- 🔒 **seccomp-bpf** システムコールフィルタリング（60以上の危険なシステムコールをブロック）
- 📊 **リソース制限** - CPU、メモリ、ファイルサイズ、オープンファイル数
- 🌐 **ネットワーク隔離** - 全てのsocket操作をブロック
- 🧵 **スレッドセーフ** - forkをブロックしながらスレッドを許可
- 🏔️ **Landlock** - ファイルシステムサンドボックス（カーネル5.13以降）
- ⚡ **低オーバーヘッド** - 約1.5msの起動コスト
- 🔧 **設定可能** - 各セキュリティ機能を個別に有効/無効化
- 🚫 **root不要** - 純粋なユーザースペース実装

## 攻撃防御マトリクス

| 攻撃 | 防御 | 技術 | テスト | オプション |
|------|------|------|:------:|------------|
| **ネットワーク外部送信** | socketシステムコールをブロック | seccomp-bpf | ✅ | `--no-network` |
| **Fork爆弾** | CLONE_THREAD=0のcloneをブロック | seccomp-bpf | ✅ | `--no-fork` |
| **メモリ爆弾** | 仮想メモリを制限 | RLIMIT_AS | ✅ | `--mem MB` |
| **CPU枯渇** | CPU時間を制限 | RLIMIT_CPU | ✅ | `--cpu SEC` |
| **ディスク充填** | ファイルサイズを制限 | RLIMIT_FSIZE | ✅ | `--fsize MB` |
| **FD枯渇** | オープンファイル数を制限 | RLIMIT_NOFILE | ✅ | `--nofile N` |
| **無限ループ** | 壁時計タイムアウト | SIGALRM+SIGKILL | ✅ | `--timeout SEC` |
| **プロセスデバッグ** | ptraceをブロック | seccomp-bpf | ✅ | `--no-dangerous` |
| **カーネル悪用** | bpf、io_uringをブロック | seccomp-bpf | ✅ | `--no-dangerous` |
| **コンテナ脱出** | unshare、setnsをブロック | seccomp-bpf | ✅ | `--no-dangerous` |
| **権限昇格** | NO_NEW_PRIVS | prctl | ✅ | デフォルト有効 |
| **環境変数漏洩** | 環境変数をサニタイズ | clearenv | ✅ | `--clean-env` |
| **シンボリックリンク攻撃** | symlink/linkをブロック | seccomp-bpf | ✅ | `--no-dangerous` |
| **ファイルアクセス** | パスベースの制限 | Landlock | ✅ | `--landlock --ro/--rw` |
| **出力フラッド** | 出力サイズを制限 | pipe + 切り捨て | ✅ | `--max-output N` |

## クイックスタート

```bash
# ビルド
make

# ネットワークをブロック
./sandlock --no-network -- curl https://evil.com
# エラー: 操作は許可されていません

# リソースを制限
./sandlock --cpu 5 --mem 64 -- python3 heavy_script.py

# 完全なサンドボックス
./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- ./untrusted
```

## インストール

```bash
# ソースからビルド（libseccomp-devが必要）
sudo apt install libseccomp-dev  # Debian/Ubuntu
make
sudo make install

# またはバイナリをコピー
cp sandlock /usr/local/bin/
```

## 使用方法

```
sandlock [オプション] -- コマンド [引数...]

リソース制限:
  --cpu SEC          CPU時間制限（秒）
  --mem MB           メモリ制限（MB）
  --fsize MB         最大ファイルサイズ（MB）
  --nofile N         最大オープンファイル数
  --nproc N          最大プロセス数（ユーザーごと）
  --timeout SEC      壁時計タイムアウト（秒）

セキュリティ機能:
  --no-network       全ネットワークシステムコールをブロック
  --no-fork          fork/cloneをブロック（スレッドは許可）
  --no-dangerous     危険なシステムコールをブロック（デフォルト有効）
  --allow-dangerous  危険なシステムコールのブロックを無効化
  --clean-env        環境変数をサニタイズ

Landlock (カーネル5.13以降):
  --landlock         Landlockファイルシステムサンドボックスを有効化
  --ro PATH          読み取り専用パスを追加（繰り返し可能）
  --rw PATH          読み書きパスを追加（繰り返し可能）

I/O制御:
  --pipe-io          I/Oをパイプでラップ
  --max-output N     出力サイズを制限（バイト）

隔離:
  --isolate-tmp      プライベートな/tmpディレクトリを使用
  --workdir DIR      作業ディレクトリを設定

その他:
  -v, --verbose      詳細出力
  --features         利用可能な機能を表示
  -h, --help         ヘルプを表示
  --version          バージョンを表示
```

## 例

### 信頼できないコードを実行

```bash
# 学生のコード提出
sandlock --no-network --no-fork --clean-env \
         --cpu 5 --mem 256 --timeout 30 \
         -- python3 student_code.py
```

### ファイルシステムサンドボックス (Landlock)

```bash
# /tmp（読み書き）と/usr（読み取り専用）のみ許可
sandlock --landlock --rw /tmp --ro /usr --ro /lib --ro /lib64 \
         -- python3 -c "open('/etc/passwd')"  # ブロックされます！
```

### 出力制限

```bash
# 出力を1MBに制限
sandlock --pipe-io --max-output 1048576 -- ./verbose_program
```

## ブロックされるシステムコール (--no-dangerous)

| カテゴリ | システムコール |
|----------|----------------|
| デバッグ | ptrace, process_vm_readv, process_vm_writev |
| カーネル | bpf, io_uring_*, userfaultfd, perf_event_open |
| 名前空間 | unshare, setns |
| ファイルシステム | mount, umount2, chroot, pivot_root, symlink, link |
| システム | reboot, kexec_*, init_module, *_module |
| 監視 | inotify_*, fanotify_* |
| キー | keyctl, add_key, request_key |
| ハードウェア | ioperm, iopl, modify_ldt |
| 時間 | settimeofday, clock_settime, adjtimex |
| その他 | personality, quotactl, nfsservctl |

## セキュリティモデル

```
┌────────────────────────────────────────┐
│         信頼できないプロセス            │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │   Landlock (カーネル5.13以降)    │  │
│  │    (ファイルシステムアクセス制御)  │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │         seccomp-bpf              │  │
│  │    (システムコールフィルタ層)     │  │
│  │  • 60以上のシステムコールをブロック│  │
│  │  • ネットワークは任意でブロック    │  │
│  │  • Forkは任意でブロック           │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │           rlimits                │  │
│  │       (リソース制限層)            │  │
│  │  • CPU、メモリ、ファイル          │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │      prctl(NO_NEW_PRIVS)         │  │
│  │       (権限昇格ブロック)          │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

## 比較

| 機能 | sandlock | Docker | Firejail | bubblewrap |
|------|:--------:|:------:|:--------:|:----------:|
| root必要 | ❌ | ✅ | ⚠️ | ⚠️ |
| オーバーヘッド | ~1.5ms | ~100ms | ~50ms | ~10ms |
| ネットワーク隔離 | ✅ | ✅ | ✅ | ✅ |
| ファイルシステムサンドボックス | ✅* | ✅ | ✅ | ✅ |
| リソース制限 | ✅ | ✅ | ✅ | ❌ |
| システムコールフィルタ | ✅ | ✅ | ✅ | ✅ |
| 複雑さ | 低 | 高 | 中 | 中 |

*Landlockはカーネル5.13以降が必要

## 既知の制限

- `/proc`は読み取り可能（mount namespaceなしのLinux制限）
- `RLIMIT_NPROC`はサンドボックスごとではなくユーザーごと
- システムに`libseccomp`が必要
- Linuxのみ（seccomp-bpfを使用）
- Landlockはカーネル5.13以降が必要（古いカーネルでは優雅にフォールバック）

## テスト

```bash
# テストスイートを実行（Dockerが必要）
make test

# またはLinuxで直接実行
./test.sh

# 利用可能な機能を確認
./sandlock --features
```

## ライセンス

MITライセンス - [LICENSE](LICENSE)を参照

## 貢献

貢献を歓迎します！issueまたはPRを作成してください。

## 関連プロジェクト

- [minijail](https://google.github.io/minijail/) - Googleのサンドボックスライブラリ
- [firejail](https://github.com/netblue30/firejail) - SUIDサンドボックス
- [bubblewrap](https://github.com/containers/bubblewrap) - 非特権サンドボックス
- [nsjail](https://github.com/google/nsjail) - 名前空間によるプロセス隔離
