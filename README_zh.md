# Sandlock 🔒

轻量级 Linux 用户态沙箱。无需 root 权限。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/ci.yml)
[![Security Tests](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml/badge.svg)](https://github.com/bkmashiro/Sandlock/actions/workflows/security-tests.yml)

**[English](README.md)** | **[日本語](README_ja.md)**

## 特性

- 🔒 **seccomp-bpf** 系统调用过滤（阻断 60+ 危险调用）
- 📊 **资源限制** - CPU、内存、文件大小、打开文件数
- 🌐 **网络隔离** - 阻断所有 socket 操作
- 🧵 **线程安全** - 阻断 fork 但允许线程
- 🏔️ **Landlock** - 文件系统沙箱（内核 5.13+）
- 🎯 **严格模式** - 路径级系统调用拦截（内核 5.0+）
- ⚡ **低开销** - 约 1.5ms 启动延迟
- 🔧 **可配置** - 各安全特性可单独启用/禁用
- 🚫 **无需 root** - 纯用户态实现

## 攻击防御矩阵

### 各环境防御状态

| 攻击类型 | 用户态 | Lambda+Py | Lambda+Node | Lambda+Preload | Lambda原生 |
|----------|:------:|:---------:|:-----------:|:--------------:|:----------:|
| 网络外传 | ✅ | ✅ | ✅ | ✅ | ❌ |
| 反弹Shell | ✅ | ✅ | ✅ | ✅ | ❌ |
| Fork炸弹 | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| 子进程/exec | ✅ | ✅ | ✅ | ✅ | ❌ |
| 内存耗尽 | ✅ | ✅ | ✅ | ✅ | ✅ |
| CPU耗尽 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 磁盘填满 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 死循环 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 读敏感文件 | ✅ | ✅ | ✅ | ✅ | ❌ |
| 写入/tmp外 | ✅ | ✅ | ✅ | ✅ | ✅ |
| ptrace调试 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 符号链接攻击 | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| dlopen/FFI | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| eval/exec | N/A | ✅ | ✅ | N/A | ❌ |
| 直接syscall | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| 沙箱逃逸 | ✅ | ⚠️ | ⚠️ | N/A | N/A |
| /proc泄露 | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| VPC横向移动 | N/A | ❌ | ❌ | ❌ | ❌ |
| IAM凭证窃取 | N/A | ❌ | ❌ | ❌ | ❌ |

图例: ✅ 已防御 | ⚠️ 部分 | ❌ 未防御 | N/A 不适用

**Lambda+Preload** = LD_PRELOAD + 源码扫描 + 动态链接（用于 C/C++/Rust/Go）

### 防御技术

| 攻击 | 用户态 | Lambda+Py/Node | Lambda+Preload | Lambda原生 |
|------|--------|----------------|----------------|------------|
| 网络 | seccomp | import/模块阻断 | LD_PRELOAD | ❌ 用VPC |
| Fork | seccomp | import/模块阻断 | LD_PRELOAD | Lambda限制 |
| 内存 | rlimit | rlimit | rlimit | Lambda配置 |
| CPU/超时 | rlimit | rlimit | rlimit | Lambda超时 |
| 磁盘 | rlimit | rlimit | rlimit | /tmp 512MB |
| 文件读 | Landlock/strict | restricted open() | LD_PRELOAD | ❌ |
| 文件写 | Landlock/strict | restricted open() | LD_PRELOAD | 只读rootfs |
| ptrace | seccomp | 无ctypes/ffi | Firecracker | Firecracker |
| 符号链接 | seccomp | 无os模块 | ⚠️ 部分 | ❌ |
| FFI/dlopen | seccomp | 阻断import | 源码扫描 | ❌ |
| 直接syscall | seccomp | ⚠️ 扫描 | ⚠️ 扫描 | ❌ |
| 沙箱逃逸 | seccomp | ⚠️ 部分 | N/A | N/A |

### Lambda 内置保护

| 保护 | 说明 |
|------|------|
| ✅ 只读rootfs | 无法写入 /var/task, /opt |
| ✅ Firecracker seccomp | 阻断 ptrace, mount, reboot 等 |
| ✅ 内存限制 | 每函数配置 (128MB-10GB) |
| ✅ 超时 | 每函数配置 (最长15分钟) |
| ✅ /tmp限制 | 512MB 临时存储 |
| ❌ 网络 | 默认完全出站访问 |
| ❌ 文件读取 | 可读 /etc/passwd, /proc 等 |
| ❌ 子进程 | 可以创建子进程 |

### 全栈对比: Lambda vs 用户态

**全栈用户态:**
```
seccomp-bpf + Landlock + rlimits + 语言沙箱 + 源码扫描 + clean-env
```

**全栈Lambda:**
```
VPC隔离 + rlimits + 语言沙箱 + LD_PRELOAD + 源码扫描 + clean-env
```

| 攻击 | 全栈用户态 | 全栈Lambda | 绕过难度 |
|------|:----------:|:----------:|:--------:|
| 网络外传 | ✅ seccomp+lang | ✅ VPC+lang+preload | 🔴 不可能 |
| 反弹Shell | ✅ seccomp+lang | ✅ VPC+lang+preload | 🔴 不可能 |
| Fork/子进程 | ✅ seccomp+lang | ✅ lang+preload | 🔴 极难 |
| 内存/CPU/磁盘 | ✅ rlimit | ✅ rlimit+Lambda | 🔴 不可能 |
| 读敏感文件 | ✅ Landlock+lang | ✅ lang+preload | 🔴 极难 |
| 写入/tmp外 | ✅ Landlock | ✅ Lambda rootfs | 🔴 不可能 |
| ptrace | ✅ seccomp | ✅ Firecracker | 🔴 不可能 |
| 直接syscall | ✅ seccomp | ⚠️ 仅扫描 | 🟡 难 |
| dlopen/FFI | ✅ seccomp+lang | ✅ lang+scanner | 🔴 极难 |
| 沙箱逃逸 | ✅ seccomp | ⚠️ lang+scanner | 🟡 难 |
| /proc泄露 | ⚠️ 部分 | ⚠️ 部分 | 🟢 中等 |
| VPC横向 | N/A | ✅ VPC隔离 | 🔴 不可能 |
| 内核0day | ⚠️ | ⚠️ | 🔴 需要0day |

**安全等级:**

| 配置 | 安全等级 | 适用场景 |
|------|:--------:|----------|
| 全栈用户态 | 🟢🟢🟢 | 最高安全，任意不信任代码 |
| 全栈Lambda | 🟢🟢 | 生产环境学生代码 |
| Lambda + 语言沙箱 | 🟡 | 基本防护 |
| Lambda原生 | 🟠 | 不建议用于不信任代码 |

## 语言沙箱

### Python 沙箱

```bash
python lang/python/sandbox.py user_code.py --timeout 5 --memory 128
```

**阻断:** `socket`, `subprocess`, `os`, `ctypes`, `mmap`, `pickle`
**允许:** `math`, `json`, `re`, `collections`, `datetime`

### JavaScript 沙箱

```bash
# VM隔离（更强，API受限）
node lang/javascript/sandbox.js user_code.js --timeout 5000

# 运行时包装（完整Node API，模块阻断）
node lang/javascript/wrapper.js user_code.js
```

### 源码扫描器

```bash
python lang/scanner/scanner.py code.c --json
```

**检测:** `asm()`, `syscall`, `int 0x80`, `_start()`, `ctypes`, `dlopen`

### LD_PRELOAD Hook

```bash
cd lang/preload && make

LD_PRELOAD=./sandbox_preload.so \
  SANDBOX_NO_NETWORK=1 \
  SANDBOX_NO_FORK=1 \
  ./user_program
```

⚠️ 可被内联汇编绕过。配合源码扫描使用。

## 快速开始

```bash
# 编译
make

# 阻断网络
./sandlock --no-network -- curl https://evil.com

# 限制资源
./sandlock --cpu 5 --mem 64 -- python3 heavy_script.py

# 全沙箱
./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- ./untrusted
```

## 安装

```bash
# 从源码编译（需要 libseccomp-dev）
sudo apt install libseccomp-dev
make
sudo make install
```

## 许可证

MIT License - 见 [LICENSE](LICENSE)
