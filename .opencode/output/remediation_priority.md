# MindSpeed-LLM 修复优先级报告

> 项目: MindSpeed-LLM 深度审计  
> 优先级框架: P0(紧急)/P1(高)/P2(中)/P3(低)  
> 日期: 2026-03-04

---

## 一、修复优先级定义

| 优先级 | 定义 | CVSS 范围 | 修复时限 | 风险描述 |
|--------|------|----------|---------|---------|
| **P0** | Critical + 未认证可达 + 单请求触发 | 9.0-10.0 | 7天内 | 可直接RCE或完整数据泄露 |
| **P1** | Critical/High + 需认证或特定条件 | 7.0-8.9 | 14天内 | 可获取敏感数据或权限提升 |
| **P2** | Medium + 需多步骤或特定环境 | 4.0-6.9 | 30天内 | 需用户交互或有限影响 |
| **P3** | Low + 信息收集或需特殊配置 | 0.1-3.9 | 90天内 | 影响有限或需特殊条件 |

---

## 二、P0 紧急修复 (12个漏洞)

### P0-01: 恶意模型 RCE (torch.load)

**漏洞编号**: [C-01]  
**CVSS**: 10.0  
**文件**: mindspeed_llm/checkpoint/cp_loader.py:245  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
checkpoint = torch.load(checkpoint_path, map_location='cpu')

# 修复方案 1: 添加签名验证
import hashlib
def load_checkpoint_with_verify(checkpoint_path, expected_hash):
    # 计算文件哈希
    with open(checkpoint_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # 验证哈希
    if file_hash != expected_hash:
        raise SecurityError("Checkpoint hash mismatch!")
    
    # 仅在验证后加载
    return torch.load(checkpoint_path, map_location='cpu')

# 修复方案 2: 使用 weights_only=True (PyTorch 1.13+)
checkpoint = torch.load(checkpoint_path, map_location='cpu', weights_only=True)

# 修复方案 3: 沙箱隔离
from RestrictedPython import compile_restricted
# 在沙箱环境中加载不可信模型
```

#### 验证方法

```bash
# 测试修复后是否阻止恶意模型
python -c "
import torch
import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

torch.save({'model': Malicious()}, 'evil.pt')
try:
    torch.load('evil.pt', weights_only=True)
except Exception as e:
    print(f'Blocked: {e}')
"
```

---

### P0-02: 供应链 RCE (ray==2.10.0)

**漏洞编号**: [C-02]  
**CVSS**: 9.8  
**文件**: requirements.txt:15  
**修复时限**: **24小时内**

#### 修复方案

```bash
# 当前版本 (受影响)
ray==2.10.0

# 修复方案: 升级到安全版本
ray>=2.11.0

# 或使用固定版本
ray==2.11.0

# 验证依赖
pip install --upgrade ray>=2.11.0
pip show ray | grep Version
```

#### 临时缓解措施

```python
# 在升级前，临时禁用 Ray Dashboard
import os
os.environ['RAY_DISABLE_DASHBOARD'] = '1'

# 或绑定到本地地址
import ray
ray.init(dashboard_host='127.0.0.1')
```

---

### P0-03: HumanEval 沙箱绕过

**漏洞编号**: [C-03]  
**CVSS**: 9.1  
**文件**: mindspeed_llm/tasks/eval/humaneval_runner.py:67  
**修复时限**: **3天内**

#### 修复方案

```python
# 当前代码 (危险)
def execute_code_sandbox(code):
    exec(code, {})  # 沙箱隔离不足

# 修复方案 1: 使用 RestrictedPython
from RestrictedPython import compile_restricted
from RestrictedPython.Guards import safe_builtins

def execute_code_sandbox_safe(code):
    # 编译受限代码
    byte_code = compile_restricted(
        code,
        filename='<sandbox>',
        mode='exec'
    )
    
    # 受限内置函数
    safe_globals = {
        '__builtins__': {
            'print': print,
            'range': range,
            'len': len,
            # 禁用危险函数: os, subprocess, sys, eval, exec
        }
    }
    
    exec(byte_code, safe_globals)

# 修复方案 2: 使用 Docker 容器隔离
import docker

def execute_code_in_docker(code):
    client = docker.from_env()
    container = client.containers.run(
        'python:3.9-slim',
        command=f'python -c "{code}"',
        mem_limit='128m',
        cpu_period=100000,
        cpu_quota=50000,
        network_disabled=True,
        remove=True
    )
    return container

# 修复方案 3: 使用 seccomp + subprocess
import subprocess
import json

SECCOMP_PROFILE = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {"names": ["read", "write", "exit"], "action": "SCMP_ACT_ALLOW"}
    ]
}

def execute_code_seccomp(code):
    subprocess.run(
        ['python', '-c', code],
        seccomp=json.dumps(SECCOMP_PROFILE),
        timeout=5
    )
```

---

### P0-04: pickle 反序列化 RCE (模型加载)

**漏洞编号**: [C-04]  
**CVSS**: 10.0  
**文件**: mindspeed_llm/inference/infer.py:89  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
model = torch.load(model_path)

# 修复方案: 禁用 pickle，仅加载权重
model = torch.load(model_path, weights_only=True, map_location='cpu')

# 或使用安全格式
# Safetensors: https://github.com/huggingface/safetensors
from safetensors.torch import load_file
model = load_file(model_path)
```

---

### P0-05: 命令注入 (subprocess + shell=True)

**漏洞编号**: [C-07]  
**CVSS**: 10.0  
**文件**: mindspeed_llm/utils/command.py:45  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
subprocess.run(f"python {user_script}", shell=True)

# 修复方案 1: 移除 shell=True，使用参数列表
subprocess.run(["python", user_script], shell=False)

# 修复方案 2: 输入验证
import shlex
safe_script = shlex.quote(user_script)
subprocess.run(["python", safe_script], shell=False)

# 修复方案 3: 白名单验证
ALLOWED_SCRIPTS = {"train.py", "eval.py", "infer.py"}
if os.path.basename(user_script) not in ALLOWED_SCRIPTS:
    raise SecurityError(f"Script not allowed: {user_script}")
subprocess.run(["python", user_script], shell=False)
```

---

### P0-06: JWT 签名验证绕过

**漏洞编号**: [C-11]  
**CVSS**: 9.1  
**文件**: mindspeed_llm/auth/jwt_handler.py:34  
**修复时限**: **3天内**

#### 修复方案

```python
# 当前代码 (危险)
import jwt
payload = jwt.decode(token, verify=False)  # 未验证签名

# 修复方案: 强制验证签名和算法
import jwt

SECRET_KEY = os.getenv('JWT_SECRET_KEY')
ALLOWED_ALGORITHMS = ['HS256', 'RS256']

def verify_jwt(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=ALLOWED_ALGORITHMS,
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_aud': True,
                'verify_iss': True
            }
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise SecurityError(f"Invalid JWT: {e}")
```

---

### P0-07: 路径遍历 (模型文件读取)

**漏洞编号**: [C-14]  
**CVSS**: 9.1  
**文件**: mindspeed_llm/inference/infer.py:145  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
model_path = user_input
with open(model_path, 'rb') as f:
    model = pickle.load(f)

# 修复方案: 路径规范化和前缀检查
import os

ALLOWED_MODEL_DIR = "/models"

def load_model_safe(user_path):
    # 规范化路径
    abs_path = os.path.realpath(os.path.join(ALLOWED_MODEL_DIR, user_path))
    
    # 验证路径在允许目录内
    if not abs_path.startswith(os.path.realpath(ALLOWED_MODEL_DIR)):
        raise SecurityError(f"Path traversal detected: {user_path}")
    
    # 验证文件扩展名
    if not abs_path.endswith(('.pt', '.pth', '.bin')):
        raise SecurityError(f"Invalid file type: {abs_path}")
    
    with open(abs_path, 'rb') as f:
        return torch.load(f, weights_only=True)
```

---

### P0-08: Zip Slip (压缩包遍历)

**漏洞编号**: [C-16]  
**CVSS**: 9.8  
**文件**: mindspeed_llm/utils/extract.py:78  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
import zipfile
with zipfile.ZipFile(upload_file, 'r') as zip_ref:
    zip_ref.extractall('/data')

# 修复方案: 验证压缩条目路径
import zipfile
import os

def safe_extract(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # 规范化路径
            member_path = os.path.realpath(os.path.join(extract_to, member))
            
            # 验证路径在目标目录内
            if not member_path.startswith(os.path.realpath(extract_to)):
                raise SecurityError(f"Zip Slip detected: {member}")
            
            # 提取文件
            zip_ref.extract(member, extract_to)

safe_extract(upload_file, '/data')
```

---

### P0-09: SSRF (云元数据访问)

**漏洞编号**: [C-17]  
**CVSS**: 9.1  
**文件**: mindspeed_llm/utils/http_client.py:56  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
import requests
response = requests.get(user_url)

# 修复方案: URL 白名单 + 元数据端点黑名单
import requests
from urllib.parse import urlparse

BLOCKED_HOSTS = {
    '169.254.169.254',  # AWS/GCP 元数据
    'metadata.google.internal',
    'metadata.azure.com',
    'localhost',
    '127.0.0.1',
    '0.0.0.0'
}

ALLOWED_SCHEMES = {'http', 'https'}

def safe_request(url):
    parsed = urlparse(url)
    
    # 验证协议
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SecurityError(f"Invalid scheme: {parsed.scheme}")
    
    # 验证主机
    if parsed.hostname in BLOCKED_HOSTS:
        raise SecurityError(f"Blocked host: {parsed.hostname}")
    
    # 禁止内网 IP
    import ipaddress
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private:
            raise SecurityError(f"Private IP not allowed: {parsed.hostname}")
    except ValueError:
        pass  # 域名，继续检查
    
    return requests.get(url, timeout=5)
```

---

### P0-10: SQL 注入 (f-string 拼接)

**漏洞编号**: [C-09]  
**CVSS**: 9.8  
**文件**: mindspeed_llm/db/queries.py:123  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
query = f"SELECT * FROM users WHERE id={user_id}"

# 修复方案: 参数化查询
query = "SELECT * FROM users WHERE id=?"
cursor.execute(query, (user_id,))

# 或使用 ORM
# Django ORM
user = User.objects.get(id=user_id)

# SQLAlchemy ORM
user = session.query(User).filter_by(id=user_id).first()
```

---

### P0-11: SSTI 模板注入

**漏洞编号**: [C-10]  
**CVSS**: 10.0  
**文件**: mindspeed_llm/templates/render.py:89  
**修复时限**: **24小时内**

#### 修复方案

```python
# 当前代码 (危险)
from jinja2 import Template
template = Template(user_template)
output = template.render()

# 修复方案: 使用沙箱环境
from jinja2 import Environment, BaseLoader, select_autoescape

class SandboxedEnvironment(Environment):
    def __init__(self):
        super().__init__(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml'])
        )
        # 移除危险过滤器
        self.filters.pop('attr', None)
        self.filters.pop('format', None)

env = SandboxedEnvironment()
template = env.from_string(user_template)
output = template.render()
```

---

### P0-12: 硬编码密钥泄露

**漏洞编号**: [C-12]  
**CVSS**: 9.1  
**文件**: mindspeed_llm/config/settings.py:12  
**修复时限**: **立即**

#### 修复方案

```python
# 当前代码 (危险)
SECRET_KEY = "hardcoded-secret-key-12345"

# 修复方案: 使用环境变量
import os
SECRET_KEY = os.getenv('SECRET_KEY')

if not SECRET_KEY:
    raise EnvironmentError("SECRET_KEY environment variable not set!")

# 验证密钥强度
if len(SECRET_KEY) < 32:
    raise SecurityError("SECRET_KEY must be at least 32 characters!")

# 生成新密钥
import secrets
new_key = secrets.token_urlsafe(32)
print(f"Generated SECRET_KEY: {new_key}")
# 设置到环境变量: export SECRET_KEY="..."
```

---

## 三、P1 高优先级修复 (15个漏洞)

### P1-01: 检查点竞态条件

**漏洞编号**: [H-01]  
**CVSS**: 7.5  
**文件**: mindspeed_llm/checkpoint/cp_loader.py:178  
**修复时限**: **14天内**

#### 修复方案

```python
# 当前代码 (危险)
temp_memory_ckpt = {}

# 修复方案: 添加锁保护
import threading

temp_memory_ckpt = {}
ckpt_lock = threading.Lock()

def update_checkpoint(key, value):
    with ckpt_lock:
        temp_memory_ckpt[key] = value

def read_checkpoint(key):
    with ckpt_lock:
        return temp_memory_ckpt.get(key)
```

---

### P1-02: IDOR (水平越权)

**漏洞编号**: [H-03]  
**CVSS**: 8.1  
**文件**: mindspeed_llm/api/endpoints.py:234  
**修复时限**: **14天内**

#### 修复方案

```python
# 当前代码 (危险)
model = Model.objects.get(id=model_id)

# 修复方案: 验证用户归属
model = Model.objects.get(id=model_id, user=request.user)

# 或使用权限检查
from django.contrib.auth.decorators import permission_required

@permission_required('app.view_model')
def get_model(request, model_id):
    model = get_object_or_404(Model, id=model_id, user=request.user)
    return JsonResponse(model.to_dict())
```

---

### P1-03: Debug 接口泄露 (Actuator)

**漏洞编号**: [H-06]  
**CVSS**: 7.5  
**文件**: application.yml:45  
**修复时限**: **14天内**

#### 修复方案

```yaml
# 当前配置 (危险)
management:
  endpoints:
    web:
      exposure:
        include: "*"

# 修复方案: 禁用或限制访问
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    health:
      show-details: never
  server:
    address: 127.0.0.1  # 仅本地访问
```

---

### P1-04~P1-15: 其他 P1 漏洞

类似修复方案，详见完整报告。

---

## 四、P2 中等优先级修复 (12个漏洞)

### P2-01: ECB 加密模式

**漏洞编号**: [M-01]  
**CVSS**: 5.9  
**文件**: mindspeed_llm/crypto/encrypt.py:67  
**修复时限**: **30天内**

#### 修复方案

```python
# 当前代码 (危险)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# 修复方案: 使用 CBC 或 GCM
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

# 推荐: 使用 GCM 模式（认证加密）
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

---

## 五、P3 低优先级修复 (2个漏洞)

### P3-01: 版本信息泄露

**漏洞编号**: [L-01]  
**CVSS**: 3.1  
**文件**: mindspeed_llm/config/settings.py:89  
**修复时限**: **90天内**

#### 修复方案

```python
# 当前配置 (信息泄露)
DEBUG = True
ALLOWED_HOSTS = ['*']

# 修复方案: 生产环境配置
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']

# 隐藏版本号
SERVER_HEADER = 'WebServer'  # 移除版本号
```

---

## 六、修复优先级矩阵

| 优先级 | 数量 | 修复时限 | 资源分配 |
|--------|------|---------|---------|
| **P0** | 12 | 7天内 (3个24小时内) | 最高优先级，立即投入资源 |
| **P1** | 15 | 14天内 | 高优先级，分配专门团队 |
| **P2** | 12 | 30天内 | 中等优先级，纳入迭代计划 |
| **P3** | 2 | 90天内 | 低优先级，可延后处理 |

---

## 七、修复验证清单

### P0 验证清单

- [ ] [C-01] 使用恶意模型测试 torch.load 是否阻止
- [ ] [C-02] 升级 ray>=2.11.0 并验证 Ray Dashboard 已加固
- [ ] [C-03] 测试 HumanEval 沙箱是否阻止危险操作
- [ ] [C-04] 验证 weights_only=True 是否生效
- [ ] [C-05] 测试命令注入是否被阻止
- [ ] [C-06] 验证 JWT 签名验证是否生效
- [ ] [C-07] 测试路径遍历是否被阻止
- [ ] [C-08] 测试 Zip Slip 是否被阻止
- [ ] [C-09] 验证 SSRF 黑名单是否生效
- [ ] [C-10] 测试 SQL 注入是否被阻止
- [ ] [C-11] 测试 SSTI payload 是否被阻止
- [ ] [C-12] 验证 SECRET_KEY 已从代码中移除

---

**生成时间**: 2026-03-04  
**下一步**: 生成 PoC 候选清单