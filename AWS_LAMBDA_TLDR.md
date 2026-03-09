# AWS Lambda Sandbox - TL;DR

## One-Line Summary

**Lambda Full-Stack = VPC isolation + Language sandbox + LD_PRELOAD + Source scanner + rlimits → 🟢🟢 Production Ready**

---

## What We CAN Defend ✅

| Attack | Defense Technology | Result |
|--------|-------------------|:------:|
| Network exfiltration / Reverse shell | VPC (no NAT) + Language sandbox + LD_PRELOAD | ✅ Blocked |
| Fork bomb | Language sandbox + LD_PRELOAD | ✅ Blocked |
| subprocess / exec | Language sandbox + LD_PRELOAD | ✅ Blocked |
| Memory / CPU exhaustion | rlimits + Lambda config | ✅ Blocked |
| Disk filling | rlimits + /tmp 512MB limit | ✅ Blocked |
| Read sensitive files | Language sandbox restricted open() | ✅ Blocked |
| Write outside /tmp | Lambda read-only rootfs | ✅ Blocked |
| ptrace debugging | Firecracker seccomp | ✅ Blocked |
| dlopen / FFI | Language sandbox + Source scanner | ✅ Blocked |
| eval / exec (dynamic) | Language sandbox restricted builtins | ✅ Blocked |

---

## What We CANNOT Fully Defend ⚠️

| Attack | Reason | Mitigation |
|--------|--------|------------|
| Direct syscall (inline asm) | No seccomp, language-level cannot intercept | Source scanner detects asm |
| Python `__subclasses__` escape | Language feature cannot be fully blocked | Restricted builtins (partial) |
| /proc info leak | Linux limitation, cannot prevent reads | clean-env removes sensitive vars |
| VPC lateral movement | Requires AWS-level configuration | Security Groups isolation |
| IAM credential theft | AWS_* environment variables | Minimal IAM role |

---

## Possible Attack Paths 🔴

| Attack | Condition | Risk Level |
|--------|-----------|:----------:|
| Inline asm direct syscall | Bypass source scanner | 🟡 Requires advanced skills |
| C extension embedded syscall | Using third-party C extensions | 🟡 Block third-party extensions |
| Timing side-channels | Multiple executions for timing analysis | 🟢 Low risk |
| Kernel 0-day | Exploit unknown vulnerability | 🔴 Cannot defend, but very rare |

---

## Configuration

### 1. Lambda Function Config (serverless.yml)

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
    
    # VPC isolation (critical!)
    vpc:
      securityGroupIds:
        - !Ref NoEgressSecurityGroup
      subnetIds:
        - !Ref PrivateSubnet
    
    # Minimal IAM
    role: !GetAtt MinimalLambdaRole.Arn
    
    environment:
      SANDLOCK_TIMEOUT: "5"
      SANDLOCK_MEMORY: "128"

resources:
  Resources:
    # Security Group: deny all egress
    NoEgressSecurityGroup:
      Type: AWS::EC2::SecurityGroup
      Properties:
        GroupDescription: No egress
        VpcId: !Ref VPC
        SecurityGroupEgress: []  # Empty = no outbound
    
    # Private subnet: no NAT gateway
    PrivateSubnet:
      Type: AWS::EC2::Subnet
      Properties:
        VpcId: !Ref VPC
        CidrBlock: 10.0.1.0/24
        # No route to NAT/IGW
    
    # Minimal IAM role
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

### 2. Handler Code (Python)

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
    
    # Write to temp file
    code_file = '/tmp/user_code.py'
    with open(code_file, 'w') as f:
        f.write(code)
    
    # Execute sandbox
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

### 3. Handler Code (Node.js)

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

### 4. Compiled Languages (C/Go/Rust)

```python
# handler.py for compiled languages
import subprocess
import json
import os

def run(event, context):
    code = event.get('code', '')
    lang = event.get('language', 'c')
    
    # 1. Source code scanning
    scan_result = subprocess.run(
        ['python3', '/var/task/lang/scanner/scanner.py', 
         '--stdin', '--json'],
        input=code, text=True, capture_output=True
    )
    scan = json.loads(scan_result.stdout)
    
    if not scan['clean']:
        return {'success': False, 'error': 'Dangerous code detected', 
                'findings': scan['findings']}
    
    # 2. Compile (force dynamic linking)
    with open('/tmp/code.c', 'w') as f:
        f.write(code)
    
    subprocess.run([
        'gcc', '-o', '/tmp/program', '/tmp/code.c',
        '-dynamic',  # Force dynamic linking
        '-fPIE', '-pie',  # Position independent
    ], check=True)
    
    # 3. Execute with LD_PRELOAD
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

## Recommended Parameters

### Resource Limits

| Parameter | Student Code | Compute Task | Notes |
|-----------|:------------:|:------------:|-------|
| timeout | 5s | 30s | Lambda + internal double timeout |
| memory | 128MB | 512MB | Lambda configuration |
| cpu | 2s | 10s | RLIMIT_CPU |
| fsize | 10MB | 50MB | Output file size |

### Security Configuration

| Config | Required | Recommended | Notes |
|--------|:--------:|:-----------:|-------|
| VPC no-egress | ✅ | - | Blocks network attacks |
| Minimal IAM | ✅ | - | CloudWatch logs only |
| Language sandbox | ✅ | - | Python/Node.js |
| Source scanner | - | ✅ | Required for compiled langs |
| LD_PRELOAD | - | ✅ | Extra layer for compiled langs |
| clean-env | - | ✅ | Remove AWS credentials |

---

## Quick Checklist

```
□ VPC config: Private subnet, no NAT gateway
□ Security Group: Empty egress rules
□ IAM role: Only logs:PutLogEvents
□ Lambda layer: Contains lang/ directory
□ Timeout: Lambda timeout > internal timeout
□ Test: Verify curl/socket is blocked
```

---

## Security Level Summary

| Configuration | Security Level | Notes |
|---------------|:--------------:|-------|
| Full-stack enabled | 🟢🟢 | Production ready, student code execution |
| Without VPC | 🟡 | Network attack risk |
| Without language sandbox | 🟠 | Large attack surface exposed |
| Lambda defaults only | 🔴 | Not recommended for untrusted code |

---

## Comparison with Userspace

| Capability | Lambda Full-Stack | Userspace Full-Stack |
|------------|:-----------------:|:--------------------:|
| Network blocking | ✅ VPC | ✅ seccomp |
| Process blocking | ✅ lang+preload | ✅ seccomp |
| File blocking | ✅ lang+preload | ✅ Landlock |
| Direct syscall | ⚠️ scanner | ✅ seccomp |
| Sandbox escape | ⚠️ partial | ✅ seccomp |
| **Overall** | 🟢🟢 | 🟢🟢🟢 |

**Conclusion:** Lambda full-stack approaches Userspace security level, suitable for production use.

---

*Sandlock v1.5.0 | 2026-03-09*
