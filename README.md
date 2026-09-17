# FridaPilot

**AI Agent for Frida automation & dynamic instrumentation.**

AI Agent 驱动的 Frida 自动化动态分析平台。让 Agent 完成 **目标发现 → 运行时侦察 → 脚本生成 → 注入执行 → 数据观测 → 错误修复 → 报告输出** 的闭环。

> **CLI-first 设计**：工具层完全独立，无需 LLM 也能通过 `fp` 命令完成日常 Frida 工作流。

---

## 分层架构

```text
用户 / Agent / IDE
        │
        ▼
CLI (fp) / MCP Server / Web UI / Python SDK
        │
        ▼
Agent Core（需要 LLM）
  ├─ Planner        任务规划
  ├─ Executor       工具执行
  ├─ Reflector      结果分析、错误修复
  ├─ Memory         历史、知识库
  └─ Reporter       报告生成
        │
        ▼
Tool Layer（纯 Python，无需 LLM）
  ├─ Recon Tools    进程/模块/类/方法枚举
  ├─ Script Forge   Frida 脚本模板与生成
  ├─ Injector       attach/spawn/inject/detach
  ├─ Observer       send/console/错误/性能收集
  ├─ Dump Tools     内存、字符串、对象图
  ├─ Bypass Tools   反调试、SSL pinning 绕过
  ├─ Crypto Reverse 二进制加密逆向（6 级模型）
  └─ Binary Analysis PE/ELF 解析、反汇编、Go 分析
        │
        ▼
Frida Core
  ├─ frida-python
  ├─ frida-server / USB / Remote
  └─ Target: Android / iOS / Windows / macOS / Linux / Electron
```

---

## 快速开始

```bash
# 安装
pip install fridapilot

# 列出进程
fp ps
fp ps --device usb

# Attach 并注入脚本
fp attach 1234
fp inject --target com.example.app --script hook.js

# 枚举模块、类、方法
fp recon modules --target com.example.app
fp recon classes --target com.example.app --filter "com.example.*"
fp recon methods --target com.example.app --class "com.example.MainActivity"

# 使用内置模板
fp template ssl-bypass --target com.example.app
fp template crypto-monitor --target com.example.app

# 收集消息并输出报告
fp observe --target com.example.app --script hook.js --output report.md

# （需要 LLM）自然语言任务
fp run "监控 Electron 应用所有 IPC 调用并打印参数" --target YourApp
fp run "找到 Android 登录校验函数并打印入参和返回值" --device usb --spawn com.example.app

# Python Agent 脚本（各平台一键逆向）
python -m fridapilot.scripts.electron_agent --target YourApp.exe
python -m fridapilot.scripts.android_agent --target com.example.app --device usb --spawn
python -m fridapilot.scripts.windows_agent --target YourApp.exe
```

---

## CLI 命令一览

| 命令 | 说明 | 需要 LLM |
|------|------|:---------:|
| `fp ps` | 列出目标设备上的进程 | ❌ |
| `fp attach <target>` | Attach 到目标进程 | ❌ |
| `fp spawn <package>` | Spawn 方式启动并注入 | ❌ |
| `fp detach` | 断开当前会话 | ❌ |
| `fp inject --script <file>` | 注入 Frida 脚本 | ❌ |
| `fp recon modules` | 枚举已加载模块 | ❌ |
| `fp recon classes` | 枚举 Java/ObjC 类 | ❌ |
| `fp recon methods` | 枚举类的方法 | ❌ |
| `fp recon exports` | 枚举模块导出符号 | ❌ |
| `fp template <name>` | 使用内置脚本模板 | ❌ |
| `fp observe` | 收集 send/console/异常消息 | ❌ |
| `fp dump memory` | Dump 内存区域 | ❌ |
| `fp dump strings` | 提取内存中的字符串 | ❌ |
| `fp bypass ssl-pinning` | 绕过 SSL Pinning | ❌ |
| `fp bypass anti-debug` | 绕过反调试检测 | ❌ |
| `fp report` | 生成 Markdown/JSON 报告 | ❌ |
| `fp crypto scan <binary>` | 扫描二进制文件加密指标（S-Box/API/保护等级） | ❌ |
| `fp crypto hook-bcrypt` | Hook Windows BCrypt API 捕获运行时密钥 | ❌ |
| `fp crypto bruteforce` | 暴力搜索二进制中的 AES 密钥 | ❌ |
| `fp crypto xor` | XOR 反混淆（单字节爆破 / 已知明文 / 已知密钥） | ❌ |
| `fp binary analyze-pe <file>` | PE 文件完整分析（header/section/import/export） | ❌ |
| `fp binary analyze-elf <file>` | ELF 文件完整分析（header/section/symbol） | ❌ |
| `fp binary disassemble` | 指定偏移反汇编（自动检测架构） | ❌ |
| `fp binary find-strings <file>` | 增强字符串提取（ASCII/UTF-16LE/UTF-8） | ❌ |
| `fp binary search-bytes <file> <pattern>` | 字节模式搜索（支持 `??` 通配符） | ❌ |
| `fp binary xrefs --address <addr>` | 交叉引用查找（CALL/JMP） | ❌ |
| `fp binary analyze-go <file>` | Go 二进制分析（版本/包/函数/源码路径） | ❌ |
| `fp binary find-string-rva <file>` | 定位字符串并返回 RVA（区分文件偏移/RVA） | ❌ |
| `fp binary xrefs-rva <file>` | RVA-aware 交叉引用（rip-relative 数据引用 + CALL/JMP） | ❌ |
| `fp binary disasm-rva <file>` | RVA-aware 反汇编（ImageBase 正确 + rip/call 目标标注） | ❌ |
| `fp run "<自然语言>"` | AI Agent 闭环执行任务 | ✅ |

---

## Tool Layer 详解

Tool Layer 是 FridaPilot 的核心基础，**纯 Python 实现、无 LLM 依赖**，安全人员可以直接通过 CLI 或 Python SDK 使用。

### Recon Tools — 目标侦察

- 进程枚举（`frida-ps` 封装），支持 USB / 远程 / 本地设备
- 运行时识别：Android Java/ART、iOS ObjC/Swift、Native C/C++、Electron/Node/V8
- 模块、导出符号、类、方法、线程枚举
- Electron 特化：自动区分主进程/渲染进程，识别 IPC 通道、contextBridge、Electron Fuses

### Script Forge — 脚本工厂

- 内置模板库：Java Hook、ObjC Hook、Native Hook、SSL Pinning 绕过、Crypto 监控、Electron IPC Hook、Node.js fs/child_process/net Hook
- 自动插入 `send()`、堆栈捕获、参数序列化
- 支持条件断点、采样、延迟注入
- 语法检查与静态校验

### Injector — 注入执行器

- attach / spawn / detach 全生命周期管理
- 多设备支持：USB、网络、本地
- 多会话管理：主进程、渲染进程、子进程
- 超时、崩溃检测、自动重连

### Observer — 运行时观测

- 收集 `send` 消息、console 输出、异常、崩溃
- 调用统计：次数、耗时、参数分布
- 自动识别敏感数据：token、密码、URL、加密参数
- 输出结构化 JSON 和时间线

### Dump Tools — 内存与数据提取

- 内存区域 dump
- 字符串提取
- 对象图遍历

### Bypass Tools — 绕过工具集

- SSL Pinning 绕过（多种方案）
- 反调试检测绕过
- 反 Frida 检测绕过

### Binary Analysis — 静态二进制分析（Phase 4 新增）

基于 pefile / pyelftools / capstone 的离线二进制分析工具，借鉴 binary-mcp、GhidraMCP、Capstone MCP 的设计：

```bash
# PE 文件分析
fp binary analyze-pe target.dll
fp binary analyze-pe target.dll --json

# ELF 文件分析
fp binary analyze-elf target_binary

# 反汇编（自动检测架构）
fp binary disassemble target.dll --address 0x30e94f0 --count 30

# 增强字符串提取（ASCII + UTF-16LE + UTF-8）
fp binary find-strings target.exe --filter "encrypt"
fp binary find-strings target.exe --encoding utf16le --min-len 6

# 字节模式搜索（支持 ?? 通配符）
fp binary search-bytes target.dll "4883ec20"
fp binary search-bytes target.dll "48 8b ?? 48 89"

# 交叉引用查找
fp binary xrefs target.dll --address 0x320bc20

# Go 二进制分析（提取版本/包/函数/源码路径）
fp binary analyze-go ipc-server.exe
```

功能：
- PE header/section/import/export 完整解析 + .NET 检测 + PDB 路径
- ELF header/section/symbol/dynamic_libs 解析
- 多架构反汇编（x86/x64/ARM/ARM64，自动检测）
- 三编码字符串提取 + 关键词过滤
- 字节模式搜索（支持 `??` 通配符，类似 IDA 搜索）
- CALL/JMP 交叉引用分析
- Go 二进制元数据提取（版本、包路径、函数列表、源码文件）

### RVA-aware 反汇编与交叉引用（大型 PE 精确分析）

`disassemble` / `xrefs` 把传入地址同时当作**文件偏移和虚拟地址**，只有当节区 RVA == 文件偏移且 ImageBase == 0 时才正确。对真实 PE（ImageBase 非 0、`.text` 等节区 RVA ≠ 文件偏移，尤其数百 MB 的大型 DLL），rip-relative 引用和 call/jmp 目标会解析错误，静默误导逆向。

`tools/pe_rva.py` 通过节区表在 RVA / VA / 文件偏移之间精确换算，提供 3 个 RVA-aware 命令：

```bash
# 1. 定位字符串并返回其 RVA（而非文件偏移），供后续 xref/disasm 使用
fp binary find-string-rva target.dll "field_name_a,field_name_b"
fp binary find-string-rva target.dll "宽字符" --encoding utf16le

# 2. RVA-aware 交叉引用：在指定 RVA 区间内查找对目标 RVA 的引用
#    kinds 支持 rip（rip-relative 数据引用，如代码按 RVA 取字符串/全局）、call、jmp
fp binary xrefs-rva target.dll --target 0x1234abcd --start 0x1000 --end 0x200000
fp binary xrefs-rva target.dll --target 0x1234abcd --start 0x1000 --end 0x200000 --kinds rip

# 3. RVA-aware 反汇编：ImageBase 正确，自动标注 rip-relative 目标 RVA 与 call/jmp 目标
#    --symbols 传入 'rva:name,rva:name' 可为已知地址打标签
fp binary disasm-rva target.dll --rva 0x1000 --count 60
fp binary disasm-rva target.dll --rva 0x1000 -n 60 --symbols 0x1234abcd:parse_field,0x2000:helper
```

能力：
- 节区感知的 RVA ↔ VA ↔ 文件偏移互转，`in_file()` 可识别 BSS（文件中无数据的未初始化 .data）
- rip-relative 操作数解析到目标 RVA，命中 `--symbols` 时附带符号名
- call/jmp 目标换算为 RVA 并标注
- xrefs 支持 rip-relative 数据引用扫描（定位"代码在哪里按 RVA 引用某字符串/全局"）

典型工作流：`find-string-rva` 拿到字段名 RVA → `xrefs-rva` 找到解析该字段的代码 → `disasm-rva` 反汇编确认逻辑。Python SDK 亦可 `from fridapilot.tools.pe_rva import PEImage, disassemble_rva, xrefs_to_rva, find_string_rvas`。

### Crypto Reverse — 二进制加密逆向分析

基于 6 级保护模型的二进制加密逆向工程工具，结合静态分析和 Frida 动态 Hook：

| 等级 | 保护方式 | 攻击策略 |
|:----:|---------|---------|
| L0 | 明文 Key/IV 存储在 .rdata 段 | 纯静态分析，S-Box 定位 + 邻近数据提取 |
| L1 | XOR 混淆 / 分散存储 | 静态分析 + XOR 反混淆 |
| L2 | 密钥派生 (PBKDF2/HKDF/scrypt) | 代码分析 + Frida Hook 派生材料 |
| L3 | 白盒 AES (T-table 融合) | DFA 攻击 / T-table 提取 |
| L4 | 服务端下发密钥 | Frida Hook BCrypt API / 抓包 |
| L5 | TPM/DPAPI 硬件绑定 | 目标机上 Hook CryptUnprotectData |

功能：
- PE/ELF 二进制加密指标扫描（S-Box 指纹、Crypto API 导入、加密字符串）
- 保护等级自动检测（L0-L5）
- Shannon 熵计算，识别高熵密钥候选区
- Hex 编码密钥候选提取
- Windows BCrypt API 运行时 Hook（捕获密钥、IV、明文/密文）

```bash
# 扫描二进制加密指标
fp crypto scan target.dll
fp crypto scan target.dll --json

# Hook BCrypt API 捕获运行时密钥
fp crypto hook-bcrypt --target YourApp.exe
```

---

## 各平台逆向分析脚本

FridaPilot 为每个目标平台提供 **JS 注入脚本 + Python Agent 脚本** 两套方案。JS 脚本通过 `fp inject` 注入，Python Agent 脚本可独立运行，自动 attach/spawn + 结构化输出。

### Electron（重点）

Electron 应用逆向涵盖主进程/渲染进程/IPC/Node.js/Fuses 全方位：

```bash
# JS 脚本方式
fp inject --target YourApp.exe --script fridapilot/templates/electron/comprehensive.js

# Python Agent 方式（推荐）
python -m fridapilot.scripts.electron_agent --target YourApp.exe
python -m fridapilot.scripts.electron_agent --target YourApp.exe --devtools
```

覆盖能力：
- IPC 通信全量监控：ipcRenderer.send/invoke/sendSync + ipcMain.handle/on
- contextBridge API 枚举（暴露给渲染进程的接口）
- BrowserWindow 安全配置检测（nodeIntegration/contextIsolation/sandbox）
- Electron Fuses 检测（runAsNode/cookieEncryption/nodeOptions/asarIntegrity）
- asar 包内容枚举 + package.json 解析
- Node.js 模块调用监控：fs / child_process / crypto / http / net
- 强制打开 DevTools

### Android

```bash
python -m fridapilot.scripts.android_agent --target com.example.app --device usb --spawn
```

覆盖能力：Activity 生命周期、SharedPreferences 读写、Cipher/MessageDigest 加密、OkHttp/URL 网络请求、Root 检测绕过、Intent 监控

### iOS

```bash
fp inject --target YourApp --script fridapilot/templates/ios/comprehensive.js --device usb
```

覆盖能力：ViewController 生命周期、Keychain 读写、NSURLSession 网络、CommonCrypto 加密、越狱检测绕过、UserDefaults 监控

### Windows

```bash
python -m fridapilot.scripts.windows_agent --target YourApp.exe
```

覆盖能力：BCrypt/CryptoAPI 加密、注册表操作、CreateFileW 文件操作、WinHTTP/Winsock 网络、IsDebuggerPresent/NtQueryInformationProcess 反调试绕过

### macOS

```bash
fp inject --target YourApp --script fridapilot/templates/macos/comprehensive.js
```

覆盖能力：Keychain 操作、NSURLSession 网络、NSTask 命令执行、文件操作、代码签名检查、CommonCrypto 加密

### Linux

```bash
fp inject --target your_app --script fridapilot/templates/linux/comprehensive.js
```

覆盖能力：open/openat 文件操作、connect/getaddrinfo 网络、execve/system 命令执行、OpenSSL SSL_read/SSL_write、ptrace 反调试绕过、dlopen 动态加载监控

---

## 加固绕过脚本

每个平台除了通用逆向脚本外，还提供针对常见加固方案的绕过脚本（`hardening_bypass.js`）。

### Android 加固绕过

```bash
fp inject --target com.example.app --script fridapilot/templates/android/hardening_bypass.js --device usb
```

| 加固方案 | 绕过方式 |
|---------|---------|
| **360 加固** | 检测 libjiagu.so，拦截 pthread_create 阻止反调试线程 |
| **腾讯乐固 (Legu)** | 检测 libshella-*.so，标记加固类型 |
| **梆梆加固** | 检测 libsecexe.so / libDexHelper.so |
| **通用壳** | Hook DexClassLoader / InMemoryDexClassLoader / DexFile.loadDex 捕获解壳后的 DEX |
| **反调试** | TracerPid 检测、ptrace 绕过、exit() 拦截 |
| **Frida 检测** | strstr 隐藏 frida 字符串、/proc/self/maps 过滤 |
| **SSL Pinning** | OkHttp3 / OkHttp-Kotlin / Retrofit / Apache HTTP / WebView / NetworkSecurityConfig 全覆盖 |

### iOS 加固绕过

```bash
fp inject --target YourApp --script fridapilot/templates/ios/hardening_bypass.js --device usb
```

| 加固方案 | 绕过方式 |
|---------|---------|
| **越狱检测** | fileExistsAtPath + C 层 access/stat/open + canOpenURL(cydia://) + fork() 全面拦截 |
| **Frida 检测** | 端口扫描 (27042) 拦截、dyld 镜像名过滤、strstr 字符串隐藏 |
| **反调试** | sysctl P_TRACED 清除、ptrace PT_DENY_ATTACH 绕过 |
| **SSL Pinning** | AFNetworking / TrustKit / URLSession delegate 多框架覆盖 |

### Windows 加固绕过

```bash
fp inject --target YourApp.exe --script fridapilot/templates/windows/hardening_bypass.js
```

| 加固方案 | 绕过方式 |
|---------|---------|
| **VMProtect** | PE section 名检测 (.vmp)，标记加固类型 |
| **Themida** | PE section 名检测 (.themida) |
| **反调试（全面）** | IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess (ProcessDebugPort + DebugObjectHandle + DebugFlags) / ThreadHideFromDebugger / OutputDebugString |
| **时间戳检测** | QueryPerformanceCounter 计时一致性 |
| **完整性检查** | CreateFileW 监控 .sig/.hash 文件访问 |
| **VM/沙箱检测** | GetSystemFirmwareTable (SMBIOS) 监控 |

### Electron 加固绕过

```bash
fp inject --target YourApp.exe --script fridapilot/templates/electron/hardening_bypass.js
```

| 加固方案 | 绕过方式 |
|---------|---------|
| **DevTools 限制** | 移除 devtools-opened 事件监听、移除快捷键拦截、强制打开 DevTools |
| **Electron Fuses** | 检测 RunAsNode / CookieEncryption / NodeOptions / NodeCliInspect / AsarIntegrity 等 8 项 Fuse 状态 |
| **asar 完整性** | Hook crypto.createHash 检测 asar 校验过程 |
| **代码混淆** | Hook eval() / new Function() 捕获动态执行的代码 |
| **调试检测** | 拦截高频 setInterval + debugger 关键字的反调试定时器 |
| **安全配置检测** | 枚举所有 BrowserWindow 的 nodeIntegration / contextIsolation / sandbox / webSecurity 配置 |
| **源码提取** | 自动枚举 asar 包文件树 + 读取 main entry point 源码 |

---

## MCP 生态

FridaPilot 暴露标准 MCP 工具，可被 Claude Desktop、Cursor、自研 Agent 等直接调用：

```text
# ── 动态分析（Frida）──
frida_list_processes      # 列出进程
frida_enumerate_modules   # 枚举模块（分页）
frida_enumerate_classes   # 枚举类（分页）
frida_enumerate_methods   # 枚举方法（分页）
frida_enumerate_exports   # 枚举导出符号（分页）
frida_inject_script       # 注入脚本
frida_generate_script     # 从模板生成脚本
frida_bypass_ssl          # 绕过 SSL Pinning
frida_crypto_scan         # 扫描二进制加密指标
frida_crypto_hook_bcrypt  # Hook BCrypt API 捕获密钥
frida_hook_function       # 声明式 Hook（自动生成 Interceptor）
frida_hook_batch          # 批量 Hook 多个函数
frida_read_memory         # 读取进程内存
frida_write_memory        # 写入进程内存
frida_search_memory       # 内存模式搜索
frida_call_function       # 调用目标进程函数

# ── 静态二进制分析 ──
binary_analyze_pe         # PE 文件完整分析
binary_analyze_elf        # ELF 文件完整分析
binary_disassemble        # 反汇编（自动检测架构）
binary_find_strings       # 增强字符串提取
binary_search_bytes       # 字节模式搜索（?? 通配符）
binary_xrefs              # 交叉引用查找
binary_analyze_go         # Go 二进制分析
```

生产级特性：
- **分页**：所有枚举工具支持 offset/limit 分页
- **路径白名单**：`FRIDAPILOT_ALLOWED_DIRS` 环境变量限制可分析目录
- **审计日志**：所有 MCP 工具调用自动记录
- **标准化响应**：统一 `{success, data, error, duration}` 格式

## Agent 工作流（需要 LLM）

```text
用户自然语言目标
      │
      ▼
Planner 拆解任务
      │
      ▼
Recon 发现目标与运行时
      │
      ▼
Script Forge 生成 Frida 脚本
      │
      ▼
Injector 注入并执行
      │
      ▼
Observer 收集数据
      │
      ▼
Reflector 分析是否成功
      │
  ┌───┴───┐
  │ 失败  │ → 修复脚本 → 重新注入（多轮迭代）
  └───┬───┘
      │ 成功
      ▼
Reporter 输出报告与脚本
```

---

## 项目结构

```text
fridapilot/
├── cli/                # CLI 入口（Typer + Rich）
│   ├── main.py         # fp 命令注册
│   ├── ps.py           # fp ps
│   ├── attach.py       # fp attach / spawn / detach
│   ├── inject.py       # fp inject
│   ├── recon.py        # fp recon modules/classes/methods
│   ├── template.py     # fp template
│   ├── observe.py      # fp observe
│   ├── bypass.py       # fp bypass
│   ├── crypto.py       # fp crypto scan / hook-bcrypt
│   ├── binary.py       # fp binary analyze-pe/elf/go / disassemble / strings / search
│   ├── report.py       # fp report
│   └── run.py          # fp run（需要 LLM）
├── tools/              # Tool Layer（纯 Python，无 LLM 依赖）
│   ├── recon.py        # 进程/模块/类/方法枚举
│   ├── script_forge.py # 脚本模板与生成
│   ├── injector.py     # attach/spawn/inject/detach
│   ├── observer.py     # 消息收集与统计
│   ├── dump.py         # 内存/字符串/对象图
│   ├── bypass.py       # SSL pinning / 反调试 / 反 Frida
│   ├── crypto_reverse.py # 二进制加密逆向分析（6 级保护模型）
│   └── binary_analysis.py # PE/ELF 解析、反汇编、Go 分析、字节搜索
├── templates/          # 内置 Frida 脚本模板
│   ├── android/        # Android: comprehensive.js + hardening_bypass.js
│   ├── ios/            # iOS: comprehensive.js + hardening_bypass.js
│   ├── windows/        # Windows: comprehensive.js + hardening_bypass.js
│   ├── macos/          # macOS: comprehensive.js
│   ├── linux/          # Linux: comprehensive.js
│   ├── electron/       # Electron: comprehensive.js + hardening_bypass.js
│   ├── java_hook.js    # 通用模板
│   ├── objc_hook.js
│   ├── native_hook.js
│   ├── ssl_bypass.js
│   ├── crypto_monitor.js
│   ├── electron_ipc.js
│   └── node_hook.js
├── scripts/            # Python Agent 脚本（独立运行）
│   ├── android_agent.py
│   ├── electron_agent.py
│   └── windows_agent.py
├── agent/              # Agent Core（需要 LLM）
│   ├── planner.py      # LLM 任务规划
│   ├── executor.py     # 工具调度执行
│   ├── reflector.py    # 错误诊断与修复
│   ├── memory.py       # 历史记忆与知识复用
│   ├── prompts.py      # 任务专用 prompt 模板（漏洞/加密/命名/解释）
│   └── reporter.py     # 报告生成
├── mcp/                # MCP Server
│   └── server.py
├── models/             # Pydantic 数据模型
│   └── schemas.py
└── storage/            # SQLite 持久化
    └── db.py           # 任务/脚本/Hook点/消息历史
```

---

## 技术栈

- **核心**：Python 3.11+、frida、frida-tools
- **CLI**：Typer + Rich
- **数据校验**：Pydantic
- **存储**：SQLite + SQLModel
- **MCP**：MCP Python SDK
- **静态分析**：pefile、pyelftools、capstone
- **LLM**（可选）：LiteLLM（兼容 OpenAI / Claude / 本地模型）
- **Agent**（可选）：自研 Planner / Executor / Reflector

---

## 安全与合规

- 仅用于 **授权安全测试、自有应用、CTF、安全研究**
- 目标白名单机制，禁止未授权目标
- 审计日志记录所有操作
- 只读模式、速率限制
- 敏感数据脱敏输出
- 每次任务生成可复现的脚本、日志和报告

---

## 差异化

- **闭环自动化**：生成 → 注入 → 观测 → 修复，不只是单次脚本生成
- **运行时上下文感知**：先侦察再生成，减少 LLM 幻觉
- **静态 + 动态一体化**：PE/ELF 静态分析 + Frida 动态 Hook，同一工具链覆盖完整 RE 流程
- **MCP 标准化**：23+ MCP 工具，可被 Claude Desktop / Cursor / 任意 Agent 调用
- **生产级安全**：路径白名单、审计日志、标准化错误响应
- **Electron / Node / 移动端 / Go 统一支持**
- **CLI-first**：无 LLM 也能完成完整工作流，安全人员即插即用
- **AI prompt 模板**：内置漏洞分析、加密分析、函数命名、协议逆向等专用模板

---

## 路线图

1. **Phase 1 — Frida 工具层 + CLI** ✅ 已完成
2. **Phase 1.5 — 二进制加密逆向** ✅ 已完成
3. **Phase 2 — MCP Server** ✅ 已完成
4. **Phase 3 — AI Agent 闭环** ✅ 已完成
5. **Phase 4 — 生产级工具升级** ✅ 已完成
   - 借鉴 AI 逆向工具生态（GhidraMCP/r2ai/binary-mcp/Capstone MCP/sentinel-reverse）
   - 新增静态二进制分析工具层（PE/ELF/反汇编/字符串/字节搜索/交叉引用/Go 分析）
   - MCP 工具 10→23+：新增 binary_analyze_pe/elf/go、binary_disassemble/find_strings/search_bytes/xrefs、frida_hook_function/batch、frida_read/write/search_memory、frida_call_function
   - 所有枚举工具支持分页（offset/limit）
   - 路径白名单（FRIDAPILOT_ALLOWED_DIRS）、审计日志、标准化响应格式
   - Agent prompt 模板系统（analyze_vulns/analyze_crypto/auto_name/explain_function/analyze_protocol）
   - Planner 感知全部新工具，支持静态+动态混合分析任务
6. **Phase 5 — Web UI 与生态**
   - 进程发现、attach/spawn/detach
   - 脚本注入、消息收集
   - 模块/类/方法枚举
   - 内置模板、绕过工具
   - CLI: `fp ps` / `fp attach` / `fp inject` / `fp recon` / `fp template` / `fp bypass`
2. **Phase 1.5 — 二进制加密逆向** ✅ 已完成
   - 6 级保护模型检测 (L0-L5)
   - AES S-Box 指纹 / Crypto API 检测
   - AES 密钥暴力搜索 / XOR 反混淆
   - BCrypt API 运行时 Hook
   - CLI: `fp crypto scan` / `fp crypto bruteforce` / `fp crypto xor` / `fp crypto hook-bcrypt`
3. **Phase 2 — MCP Server** ✅ 已完成
   - 暴露 11 个 MCP 工具接口
   - 支持 Claude Desktop / Cursor 调用
   - stdio 传输协议
4. **Phase 3 — AI Agent 闭环** ✅ 已完成
   - Planner: LLM 自然语言任务拆解为 Tool Layer 步骤
   - Executor: 工具调度、依赖解析、Session 管理
   - Reflector: 错误诊断（8 类模式匹配）、LLM 修复计划
   - Reporter: Markdown / JSON 报告生成
   - CLI: `fp run "自然语言"` 闭环执行
4. **Phase 4 — 报告与多设备**
   - Markdown / JSON / HTML 报告
   - USB / 远程 frida-server
   - 多进程会话管理
5. **Phase 5 — Web UI 与生态**
   - Web 控制台、时间线、脚本编辑器
   - 插件系统、社区模板

---

## License

MIT
