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
- ⚡ **低开销** - 约 1.5ms 启动延迟
- 🔧 **可配置** - 各安全特性可单独启用/禁用
- 🚫 **无需 root** - 纯用户态实现

## 攻击防御矩阵

| 攻击类型 | 防御方式 | 技术实现 | 测试 | 选项 |
|----------|----------|----------|:----:|------|
| **网络外传** | 阻断 socket 系统调用 | seccomp-bpf | ✅ | `--no-network` |
| **Fork 炸弹** | 阻断无 CLONE_THREAD 的 clone | seccomp-bpf | ✅ | `--no-fork` |
| **内存炸弹** | 限制虚拟内存 | RLIMIT_AS | ✅ | `--mem MB` |
| **CPU 耗尽** | 限制 CPU 时间 | RLIMIT_CPU | ✅ | `--cpu SEC` |
| **磁盘填满** | 限制文件大小 | RLIMIT_FSIZE | ✅ | `--fsize MB` |
| **文件描述符耗尽** | 限制打开文件数 | RLIMIT_NOFILE | ✅ | `--nofile N` |
| **死循环** | 墙钟超时 | SIGALRM+SIGKILL | ✅ | `--timeout SEC` |
| **进程调试** | 阻断 ptrace | seccomp-bpf | ✅ | `--no-dangerous` |
| **内核漏洞利用** | 阻断 bpf、io_uring | seccomp-bpf | ✅ | `--no-dangerous` |
| **容器逃逸** | 阻断 unshare、setns | seccomp-bpf | ✅ | `--no-dangerous` |
| **提权** | NO_NEW_PRIVS | prctl | ✅ | 默认开启 |
| **环境变量泄露** | 清理环境变量 | clearenv | ✅ | `--clean-env` |
| **符号链接攻击** | 阻断 symlink/link | seccomp-bpf | ✅ | `--no-dangerous` |
| **文件访问控制** | 路径白名单 | Landlock | ✅ | `--landlock --ro/--rw` |
| **输出洪水** | 限制输出大小 | pipe + 截断 | ✅ | `--max-output N` |

## 快速开始

```bash
# 编译
make

# 阻断网络
./sandlock --no-network -- curl https://evil.com
# 错误: 操作不允许

# 限制资源
./sandlock --cpu 5 --mem 64 -- python3 heavy_script.py

# 完整沙箱
./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- ./untrusted
```

## 安装

```bash
# 从源码编译 (需要 libseccomp-dev)
sudo apt install libseccomp-dev  # Debian/Ubuntu
make
sudo make install

# 或直接复制二进制
cp sandlock /usr/local/bin/
```

## 使用方法

```
sandlock [选项] -- 命令 [参数...]

资源限制:
  --cpu SEC          CPU 时间限制（秒）
  --mem MB           内存限制（MB）
  --fsize MB         最大文件大小（MB）
  --nofile N         最大打开文件数
  --nproc N          最大进程数（每用户）
  --timeout SEC      墙钟超时（秒）

安全特性:
  --no-network       阻断所有网络系统调用
  --no-fork          阻断 fork/clone（允许线程）
  --no-dangerous     阻断危险系统调用（默认开启）
  --allow-dangerous  禁用危险系统调用阻断
  --clean-env        清理环境变量

Landlock (内核 5.13+):
  --landlock         启用 Landlock 文件系统沙箱
  --ro PATH          添加只读路径（可重复）
  --rw PATH          添加读写路径（可重复）

I/O 控制:
  --pipe-io          用管道包裹 I/O
  --max-output N     限制输出大小（字节）

隔离:
  --isolate-tmp      使用私有 /tmp 目录
  --workdir DIR      设置工作目录

其他:
  -v, --verbose      详细输出
  --features         显示可用特性
  -h, --help         显示帮助
  --version          显示版本
```

## 示例

### 运行不可信代码

```bash
# 学生代码提交
sandlock --no-network --no-fork --clean-env \
         --cpu 5 --mem 256 --timeout 30 \
         -- python3 student_code.py
```

### 文件系统沙箱 (Landlock)

```bash
# 只允许 /tmp (读写) 和 /usr (只读)
sandlock --landlock --rw /tmp --ro /usr --ro /lib --ro /lib64 \
         -- python3 -c "open('/etc/passwd')"  # 被阻断！
```

### 输出限制

```bash
# 限制输出为 1MB
sandlock --pipe-io --max-output 1048576 -- ./verbose_program
```

## 阻断的系统调用 (--no-dangerous)

| 类别 | 系统调用 |
|------|----------|
| 调试 | ptrace, process_vm_readv, process_vm_writev |
| 内核 | bpf, io_uring_*, userfaultfd, perf_event_open |
| 命名空间 | unshare, setns |
| 文件系统 | mount, umount2, chroot, pivot_root, symlink, link |
| 系统 | reboot, kexec_*, init_module, *_module |
| 监控 | inotify_*, fanotify_* |
| 密钥 | keyctl, add_key, request_key |
| 硬件 | ioperm, iopl, modify_ldt |
| 时间 | settimeofday, clock_settime, adjtimex |
| 其他 | personality, quotactl, nfsservctl |

## 安全模型

```
┌────────────────────────────────────────┐
│           不可信进程                    │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │     Landlock (内核 5.13+)        │  │
│  │      (文件系统访问控制)           │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │         seccomp-bpf              │  │
│  │       (系统调用过滤层)            │  │
│  │  • 60+ 系统调用被阻断             │  │
│  │  • 网络可选阻断                   │  │
│  │  • Fork 可选阻断                  │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │           rlimits                │  │
│  │        (资源限制层)               │  │
│  │  • CPU、内存、文件                │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ┌──────────────────────────────────┐  │
│  │      prctl(NO_NEW_PRIVS)         │  │
│  │        (提权阻断)                 │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

## 对比

| 特性 | sandlock | Docker | Firejail | bubblewrap |
|------|:--------:|:------:|:--------:|:----------:|
| 需要 root | ❌ | ✅ | ⚠️ | ⚠️ |
| 开销 | ~1.5ms | ~100ms | ~50ms | ~10ms |
| 网络隔离 | ✅ | ✅ | ✅ | ✅ |
| 文件系统沙箱 | ✅* | ✅ | ✅ | ✅ |
| 资源限制 | ✅ | ✅ | ✅ | ❌ |
| 系统调用过滤 | ✅ | ✅ | ✅ | ✅ |
| 复杂度 | 低 | 高 | 中 | 中 |

*Landlock 需要内核 5.13+

## 已知限制

- `/proc` 可读（无 mount namespace 的 Linux 限制）
- `RLIMIT_NPROC` 是每用户而非每沙箱
- 需要系统安装 `libseccomp`
- 仅支持 Linux（使用 seccomp-bpf）
- Landlock 需要内核 5.13+（旧内核优雅降级）

## 测试

```bash
# 运行测试套件（需要 Docker）
make test

# 或直接在 Linux 运行
./test.sh

# 检查可用特性
./sandlock --features
```

## 许可证

MIT 许可证 - 见 [LICENSE](LICENSE)

## 贡献

欢迎贡献！请提 issue 或 PR。

## 相关项目

- [minijail](https://google.github.io/minijail/) - Google 沙箱库
- [firejail](https://github.com/netblue30/firejail) - SUID 沙箱
- [bubblewrap](https://github.com/containers/bubblewrap) - 非特权沙箱
- [nsjail](https://github.com/google/nsjail) - 基于命名空间的进程隔离
