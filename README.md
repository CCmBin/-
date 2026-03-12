# 🛡 LogAudit

> 🚀 快速开始

### 直接使用（推荐）

1. 从 [Releases](../../releases) 下载最新版压缩包

2. 解压，保持目录结构：

   ```
   LogAudit.exe
   rules/
   └── rules.yaml
   ```

3. 双击 `LogAudit.exe` 启动

### 从源码构建

**环境要求：** .NET 8 SDK、Windows x64

```bash
git clone https://github.com/your-username/LogAudit.git
cd LogAudit
dotnet restore
dotnet build
```

```bash
dotnet publish -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -o ./publish
```

发布产物在 `publish/` 目录，将 `rules/` 文件夹一并打包分发即可。

---

## 📋 支持的日志格式

解析器支持两种标准 Web 日志格式，自动识别无需手动选择。

### Combined 格式（优先匹配）

Nginx 默认格式、Apache `combined` 格式，包含 Referer 和 User-Agent：

```
223.5.5.5 - - [12/Mar/2025:10:23:01 +0800] "GET /index.php?id=1 HTTP/1.1" 200 1024 "https://example.com" "Mozilla/5.0 ..."
```

解析字段：`IP` · `时间` · `请求方法` · `URI` · `协议` · `状态码` · `响应大小` · `Referer` · `User-Agent`

### Common 格式

Apache `common` 格式，无 Referer / UA 字段：

```
223.5.5.5 - - [12/Mar/2025:10:23:01 +0800] "POST /admin/login.php HTTP/1.1" 401 512
```

解析字段：`IP` · `时间` · `请求方法` · `URI` · `协议` · `状态码` · `响应大小`

---

### 支持的文件类型

| 扩展名    | 说明                                    |
| --------- | --------------------------------------- |
| `.log`    | 标准日志文件                            |
| `.txt`    | 文本格式日志                            |
| `.access` | 部分服务器的访问日志                    |
| `.gz`     | 压缩日志（自动解压读取）                |
| 无扩展名  | 文件名含 `access` 或 `error` 时自动识别 |

> 📁 项目结构

```
LogAudit/
├── cmd/
│   └── Program.cs               # 入口
├── GUI/
│   └── MainForm.cs              # 主界面
├── Core/
│   ├── Parser/LogParser.cs      # 日志解析
│   ├── Detector/RuleEngine.cs   # 规则引擎
│   ├── Scanner/FileScanner.cs   # 文件扫描
│   ├── Analyzer/                # 流量分析
│   └── Reporter/                # 报告生成
└── rules/
    └── rules.yaml               # 规则库（157 条）
```

---

