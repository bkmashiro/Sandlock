# AWS Lambda Sandbox - TL;DR

## 一句话总结

**Lambda全栈防护 = VPC隔离 + 语言沙箱 + LD_PRELOAD + 源码扫描 + rlimits → 🟢🟢 生产可用**

---

## 能实现的安全 ✅

| 攻击 | 防御技术 | 效果 |
|------|----------|:----:|
| 网络外传/反弹Shell | VPC无NAT + 语言沙箱 + LD_PRELOAD | ✅ 完全阻断 |
| Fork炸弹 | 语言沙箱 + LD_PRELOAD | ✅ 阻断 |
| 子进程/exec | 语言沙箱 + LD_PRELOAD | ✅ 阻断 |
| 内存/CPU耗尽 | rlimits + Lambda配置 | ✅ 阻断 |
| 磁盘填满 | rlimits + /tmp 512MB限制 | ✅ 阻断 |
| 读敏感文件 | 语言沙箱 restricted open() | ✅ 阻断 |
| 写/tmp外 | Lambda只读rootfs | ✅ 阻断 |
| ptrace调试 | Firecracker seccomp | ✅ 阻断 |
| dlopen/FFI | 语言沙箱 + 源码扫描 | ✅ 阻断 |
| eval/exec动态执行 | 语言沙箱 restricted builtins | ✅ 阻断 |

---

## 无法完全实现的安全 ⚠️

| 攻击 | 原因 | 缓解措施 |
|------|------|----------|
| 直接syscall (内联汇编) | 无seccomp，语言层无法拦截 | 源码扫描检测asm |
| Python `__subclasses__` 逃逸 | 语言特性无法完全阻断 | restricted builtins部分防护 |
| /proc信息泄露 | Linux限制无法阻止读取 | clean-env清理敏感环境变量 |
| VPC内横向移动 | 需AWS层面配置 | Security Groups隔离 |
| IAM凭证窃取 | AWS_*环境变量 | 最小权限IAM角色 |

---

## 可能的攻击路径 🔴

| 攻击 | 条件 | 风险等级 |
|------|------|:--------:|
| 内联汇编直接syscall | 绕过源码扫描 | 🟡 需要高级技能 |
| C扩展内嵌syscall | 使用第三方C扩展 | 🟡 禁用第三方扩展可防 |
| 时序侧信道 | 多次执行计时分析 | 🟢 低风险 |
| 内核0day | 利用未知漏洞 | 🔴 无法防御，但概率极低 |

---

## 配置方式

### 1. Lambda函数配置 (serverless.yml)

```yaml
service: sandlock-executor

provider:
  name: aws
  runtime: python3.12
  region: eu-west-2
  
functions:
  execute:
    handler: handler.run
    timeout: 30
    memorySize: 256
    
    # VPC隔离 (关键!)
    vpc:
      securityGroupIds:
        - !Ref NoEgressSecurityGroup
      subnetIds:
        - !Ref PrivateSubnet
    
    # 最小权限IAM
    role: !GetAtt MinimalLambdaRole.Arn
    
    # 环境变量
    environment:
      SANDLOCK_TIMEOUT: "5"
      SANDLOCK_MEMORY: "128"

resources:
  Resources:
    # 安全组: 禁止所有出站
    NoEgressSecurityGroup:
      Type: AWS::EC2::SecurityGroup
      Properties:
        GroupDescription: No egress
        VpcId: !Ref VPC
        SecurityGroupEgress: []  # 空 = 无出站
    
    # 私有子网: 无NAT网关
    PrivateSubnet:
      Type: AWS::EC2::Subnet
      Properties:
        VpcId: !Ref VPC
        CidrBlock: 10.0.1.0/24
        # 无路由到NAT/IGW
    
    # 最小IAM角色
    MinimalLambdaRole:
      Type: AWS::IAM::Role
      Properties:
        AssumeRolePolicyDocument:
          Version: '2012-10-17'
          Statement:
            - Effect: Allow
              Principal:
                Service: lambda.amazonaws.com
              Action: sts:AssumeRole
        Policies:
          - PolicyName: LogsOnly
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
                - Effect: Allow
                  Action:
                    - logs:CreateLogStream
                    - logs:PutLogEvents
                  Resource: '*'
```

### 2. Handler代码 (Python)

```python
# handler.py
import subprocess
import json
import os

SANDBOX_PATH = '/var/task/lang/python/sandbox.py'

def run(event, context):
    code = event.get('code', '')
    timeout = int(os.environ.get('SANDLOCK_TIMEOUT', '5'))
    memory = int(os.environ.get('SANDLOCK_MEMORY', '128'))
    
    # 写入临时文件
    code_file = '/tmp/user_code.py'
    with open(code_file, 'w') as f:
        f.write(code)
    
    # 执行沙箱
    result = subprocess.run(
        ['python3', SANDBOX_PATH, code_file,
         '--timeout', str(timeout),
         '--memory', str(memory),
         '--json'],
        capture_output=True,
        text=True,
        timeout=timeout + 5
    )
    
    return json.loads(result.stdout)
```

### 3. Handler代码 (Node.js)

```javascript
// handler.js
const { execSync } = require('child_process');
const fs = require('fs');

const SANDBOX_PATH = '/var/task/lang/javascript/wrapper.js';

exports.run = async (event) => {
    const code = event.code || '';
    const codeFile = '/tmp/user_code.js';
    
    fs.writeFileSync(codeFile, code);
    
    try {
        const result = execSync(
            `node ${SANDBOX_PATH} ${codeFile}`,
            {
                timeout: 10000,
                env: {
                    ...process.env,
                    SANDLOCK_ALLOW_NETWORK: '0',
                    SANDLOCK_ALLOW_CHILD: '0',
                }
            }
        );
        return { success: true, output: result.toString() };
    } catch (err) {
        return { success: false, error: err.message };
    }
};
```

### 4. 编译语言 (C/Go/Rust)

```python
# handler.py for compiled languages
import subprocess
import os

def run(event, context):
    code = event.get('code', '')
    lang = event.get('language', 'c')
    
    # 1. 源码扫描
    scan_result = subprocess.run(
        ['python3', '/var/task/lang/scanner/scanner.py', 
         '--stdin', '--json'],
        input=code, text=True, capture_output=True
    )
    scan = json.loads(scan_result.stdout)
    
    if not scan['clean']:
        return {'success': False, 'error': 'Dangerous code detected', 
                'findings': scan['findings']}
    
    # 2. 编译 (强制动态链接)
    with open('/tmp/code.c', 'w') as f:
        f.write(code)
    
    subprocess.run([
        'gcc', '-o', '/tmp/program', '/tmp/code.c',
        '-dynamic',  # 强制动态链接
        '-fPIE', '-pie',  # 位置无关
    ], check=True)
    
    # 3. LD_PRELOAD执行
    env = os.environ.copy()
    env['LD_PRELOAD'] = '/var/task/lang/preload/sandbox_preload.so'
    env['SANDBOX_NO_NETWORK'] = '1'
    env['SANDBOX_NO_FORK'] = '1'
    env['SANDBOX_ALLOW_PATH'] = '/tmp'
    
    result = subprocess.run(
        ['/tmp/program'],
        capture_output=True, text=True,
        timeout=5, env=env
    )
    
    return {'success': True, 'output': result.stdout}
```

---

## 建议参数

### 资源限制

| 参数 | 学生代码 | 计算任务 | 说明 |
|------|:--------:|:--------:|------|
| timeout | 5s | 30s | Lambda + 内部双重超时 |
| memory | 128MB | 512MB | Lambda配置 |
| cpu | 2s | 10s | RLIMIT_CPU |
| fsize | 10MB | 50MB | 输出文件大小 |

### 安全配置

| 配置 | 必须 | 建议 | 说明 |
|------|:----:|:----:|------|
| VPC无出站 | ✅ | - | 阻断网络攻击 |
| 最小IAM | ✅ | - | 仅CloudWatch日志 |
| 语言沙箱 | ✅ | - | Python/Node.js |
| 源码扫描 | - | ✅ | 编译语言必须 |
| LD_PRELOAD | - | ✅ | 编译语言额外层 |
| clean-env | - | ✅ | 清理AWS凭证 |

---

## 快速检查清单

```
□ VPC配置: 私有子网，无NAT网关
□ 安全组: 出站规则为空
□ IAM角色: 仅logs:PutLogEvents
□ Lambda层: 包含lang/目录
□ 超时: Lambda timeout > 内部timeout
□ 测试: 尝试curl/socket确认阻断
```

---

## 安全等级总结

| 配置 | 安全等级 | 说明 |
|------|:--------:|------|
| 全部开启 | 🟢🟢 | 生产可用，学生代码执行 |
| 无VPC | 🟡 | 网络攻击风险 |
| 无语言沙箱 | 🟠 | 大量攻击面暴露 |
| 仅Lambda默认 | 🔴 | 不建议运行不信任代码 |

---

## 与Userspace对比

| 能力 | Lambda全栈 | Userspace全栈 |
|------|:----------:|:-------------:|
| 网络阻断 | ✅ VPC | ✅ seccomp |
| 进程阻断 | ✅ 语言+preload | ✅ seccomp |
| 文件阻断 | ✅ 语言+preload | ✅ Landlock |
| 直接syscall | ⚠️ 扫描 | ✅ seccomp |
| 沙箱逃逸 | ⚠️ 部分 | ✅ seccomp |
| **总体** | 🟢🟢 | 🟢🟢🟢 |

**结论:** Lambda全栈接近Userspace安全等级，适合生产使用。

---

*Sandlock v1.5.0 | 2026-03-09*
