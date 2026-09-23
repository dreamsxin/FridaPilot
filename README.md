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
fp template ssl-bypass
fp template crypto-monitor

# 收集消息并输出报告
fp observe --target com.example.app --script hook.js --output report.md

# （需要 LLM）自然语言任务
fp run "监控 Electron 应用所有 IPC 调用并打印参数" --target YourApp
fp run "找到 Android 登录校验函数并打印入参和返回值" --target com.example.app --device usb

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
| `fp bypass ssl-pinning` | 绕过 SSL Pinning | ❌ |
| `fp bypass anti-debug` | 绕过反调试检测 | ❌ |
| `fp report` | 生成 Markdown/JSON 报告 | ❌ |
| `fp crypto scan <binary>` | 扫描二进制文件加密指标（S-Box/API/保护等级） | ❌ |
| `fp crypto hook-bcrypt` | Hook Windows BCrypt API 捕获运行时密钥 | ❌ |
| `fp crypto bruteforce` | 暴力搜索二进制中的 AES 密钥 | ❌ |
| `fp crypto xor` | XOR 反混淆（单字节爆破 / 已知明文 / 已知密钥） | ❌ |
| `fp binary metadata <file>` | **元数据侦察（先跑这个）**：PDB GUID + 符号服务器 key、版本资源、manifest、Rich header、COFF 符号、工具链指纹、Rust 源码路径、节熵 | ❌ |
| `fp binary analyze-pe <file>` | PE 文件完整分析（header/section/import/export） | ❌ |
| `fp binary analyze-elf <file>` | ELF 文件完整分析（header/section/symbol） | ❌ |
| `fp binary disassemble` | 指定偏移反汇编（自动检测架构） | ❌ |
| `fp binary find-strings <file>` | 字符串提取（ASCII/UTF-16LE/UTF-8 + `--codepage gbk/cp932/cp1251` 等 ANSI 代码页），PE 附带 RVA/节名 | ❌ |
| `fp binary find-text <file> --text <串>` | 同一个串按多种编码同时搜（不知道编码时用），返回 RVA/节名/命中编码 | ❌ |
| `fp binary search-bytes <file> <pattern>` | 字节/十六进制搜索（支持 `??` 通配符），PE 附带 RVA/节名 | ❌ |

| `fp binary xrefs --address <addr>` | 交叉引用查找（CALL/JMP） | ❌ |
| `fp binary analyze-go <file>` | Go 二进制分析（版本/包/函数/源码路径） | ❌ |
| `fp binary find-string-rva <file>` | 定位字符串并返回 RVA（区分文件偏移/RVA） | ❌ |
| `fp binary inline-strings <file> --text <串>` | 定位代码用 `movabs` **内联构造**的字符串（无 .rdata 副本，连续字节搜索和 xref 都找不到） | ❌ |
| `fp binary index-build <file>` | 扫一遍建 rip 引用索引，之后 `xrefs-rva --kinds rip` 变成数据库查询（ntdll 实测 3.9s 建索引，查询 4.2s→~0s） | ❌ |
| `fp binary index-info [file]` | 查看索引覆盖范围 / 列出全部索引 | ❌ |
| `fp binary index-drop <file>` | 删除该文件内容对应的索引 | ❌ |
| `fp binary xrefs-rva <file>` | RVA-aware 交叉引用（rip 数据引用 + CALL/JMP）。范围默认整节（`--section`），并打印实际扫描覆盖率 | ❌ |
| `fp binary callers <file> --target <rva>` | **函数的调用方**：所有可执行节扫 call/jmp + 所有数据节扫指针槽位，给出结论句（虚函数/IDL 绑定表/thunk 没有直接 call，用这个而不是 `xrefs-rva --kinds call,jmp`） | ❌ |
| `fp binary vtable <file> --target <rva>` | 虚函数**实现地址** → 它在哪个 vtable、第几槽、MSVC RTTI 类名、安装该表的构造函数（反方向「按槽位偏移找类」静态不可解） | ❌ |
| `fp binary describe <file> --rva <rva>` | **给无名函数起名**：用函数体引用的字符串（DCHECK 留下的 `__FILE__`、`__PRETTY_FUNCTION__`、直方图名、`movabs` 立即数），分类成源码路径/符号/普通串 | ❌ |
| `fp binary callees <file> --rva <rva>` | 该函数**调用了谁**，每个 callee 同样起名（`callers` 的反方向；间接 `call rax` 在指令流里没有名字） | ❌ |


| `fp binary disasm-rva <file>` | RVA-aware 反汇编（ImageBase 正确 + rip/call 目标标注） | ❌ |
| `fp disasm view <file>` | **带符号与节区信息的反汇编列表**：每行同时给出 VA / 原始字节 / 指令 / 所属节区 / 所属函数；PE/ELF/Mach-O 通用，`--section` `--function` `--start/--end` 过滤，`--format group\|table\|json`，`--source` 附带 DWARF 源文件:行号，`--mode recursive` 只反汇编控制流可达的字节 | ❌ |
| `fp disasm sections <file>` | 节区表：VA 区间、文件偏移、读写执行权限、落在其中的符号数 | ❌ |
| `fp disasm symbols <file>` | 函数符号表：地址、大小、所属节区、名字来源（symtab/dynsym/export/coff/nlist） | ❌ |
| `fp apk analyze <apk>` | APK 静态分析（manifest/权限/组件/native 库/签名/保护特征） | ❌ |
| `fp apk dex <dex>` | DEX 分析（header/类/方法/字符串） | ❌ |
| `fp apk protections <apk>` | Root/SSL pinning/Frida/模拟器检测与加固壳特征 | ❌ |
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

### 带符号与节区信息的反汇编查看器（`fp disasm`）

`tools/disasm_view.py` 把「地址 → 节区 / 函数」的映射做成与格式无关的一层，PE / ELF / Mach-O 共用同一套输出：

```bash
# 按节区列（默认入口点，也可 --function / --start --end）
fp disasm view target.dll --section .text --count 60

# 表格视图，适合过滤与比对
fp disasm view a.out --function main --format table

# 带源文件/行号（ELF DWARF；默认关闭，因为解析 DWARF 是这里最贵的一步）
fp disasm view a.out --function main --source

# 递归下降：只反汇编控制流能到达的字节，其余标成 unreached
fp disasm view target.dll --function DllMain --mode recursive


# 机器可读，接其他工具
fp disasm view lib.so --section .text --format json --output out.json

# 地址映射本身
fp disasm sections target.dll
fp disasm symbols target.dll --pattern decrypt
```

每行同时携带：VA、文件偏移（PE 另有 RVA）、原始字节、指令、所属节区、所属函数与函数内偏移。

几个刻意的取舍：

- **地址一律是虚拟地址**（PE 已加 ImageBase，ELF 为链接期地址）；`fp binary disassemble` 的 `--address` 是文件偏移，两者不是一回事
- **不可执行节区不反汇编**，按字符串 + 十六进制行渲染。把 `.rdata` 喂给反汇编器会得到一堆永不执行的「指令」，这是这类工具最容易误导人的地方
- **函数边界分精确与推断两种**：PE 走 `.pdata`、ELF 走带 `st_size` 的 `STT_FUNC` 属于精确；PE 导出表、Mach-O `nlist` 不记录大小，只能用下一个符号推断末尾，这种情况标 `function_exact=false`（分组视图显示 `(implied bounds)`，表格视图名字后加 `?`）。两个符号之间的空隙不归任何函数，宁可留空也不硬派一个名字——`push rbp` 序言启发式在优化代码上不可靠，这里没有使用
- **Mach-O 的代码判定看节区属性而非段权限**：`__TEXT` 是 r-x 且内含 `__cstring`，只看 `VM_PROT_EXECUTE` 会把字符串字面量当代码反汇编
- **遇到数据字节会重新同步并把它标成 `bad`**，而不是像单次 `md.disasm` 那样在第一个无法解码的字节处静默结束（跳转表、对齐填充都会触发）
- **范围有上限**（默认 200 行 / 512 KB 解码），截断时在输出里说明，不假装扫完了
- **源码行号（`--source`）只覆盖 DWARF 记录的范围**：ELF 的行号表按「序列」组织，每段以 `DW_LNE_end_sequence` 结束，序列之外没有行号。常见错误实现是「二分找到不大于该地址的最后一行」，那样每个越界地址都会拿到最后一行的文件名和行号。Windows 的行号在 PDB 里而不在镜像里，所以 PE 只会告诉你 PDB 路径
- **`--mode recursive` 只反汇编控制流到达的字节**：函数体里的跳转表、内联常量、对齐填充在线性扫描下会被当成指令，而且错位重同步之后会产出程序里根本不存在的指令（fixture 里 `eb 02 / ff ff / 31 c0` 就是这个形状：线性模式给出 `push qword [rcx]`）。种子不只是起始地址，还包括范围内所有函数符号——虚函数、绑定表项、回调只通过指针到达，没有任何分支指令指向它们，只从入口递归会把它们全部漏掉。反过来，递归模式**无法证明**跳过的字节不是代码（间接跳转的目标是静态不可知的），所以未到达区间会以 `unreached` 行列出而不是丢弃，并带 `span` 字段，便于校验「解码字节 + 未到达字节 == 请求范围」。ntdll 全 `.text` 递归取 200 行实测 0.56s


### PE 逆向分析策略（决策顺序）

对任何本地 PE 文件，按以下优先级推进。每一步的结果决定后续步骤是否必要。

**Step 0 — 元数据侦察（必做，零成本）**

```bash
fp binary metadata target.dll
```

- PDB GUID → 从符号服务器拉公开符号，有符号后大部分反汇编工作可跳过
- Rust panic 路径 → 源码目录树即使 strip 后仍保留
- COFF 符号 → MinGW 编译常保留，直接给出函数名
- 节熵 >7.2 → 加壳/加密数据，先脱壳再分析
- 极少导入 + `LoadLibrary`/`GetProcAddress` → 动态 API 解析，Hook 这两个函数而非读导入表

**Step 1 — 锚点定位（字符串/字节搜索）**

```bash
fp binary find-string-rva target.dll "config_key,error_msg"
fp binary find-text target.dll --text "许可过期" --encodings utf8,utf16le,gbk
fp binary search-bytes target.dll "48 8b ?? 48 89"
```

- `find-string-rva`：已知编码时用，返回 RVA 供后续 xref。**命中都是子串命中**——输出会标出该命中所属的完整 NUL 结尾串，只有 `whole` 为真才说明镜像里存在这个独立字符串。`读 len(key)+1 字节 == key + "\0"` 这个判据只约束尾部，`ID3D12Device::CheckFeatureSupport` 会通过针对 `FeatureSupport` 的测试（实测某 Chromium DLL：18 处命中，0 处独立串）
- `find-text`：不知道编码时用，多编码同时搜
- `search-bytes`：搜常量/magic/字节模式

**Step 2 — 交叉引用（先判断目标是什么）**

目标是**函数** → 用 `fp binary callers`，不要用 `xrefs-rva --kinds call,jmp`：

```bash
fp binary callers target.dll --target 0x1c43500
fp binary callers target.dll --target 0x1c43500 --follow
```

C++ 虚函数、Blink IDL 方法（如 `HTMLCanvasElement::toDataURL`，由 V8 绑定层从生成的方法表里调）、导入 thunk、回调——这些被调用者在整个镜像里**没有任何直接 call/jmp 指令**，它们的地址只以一个 8 字节指针的形式存在于数据节。所以「谁 call 这个函数」对它们必然返回 0，热函数和死代码的输出完全一样。

`callers` 同时扫描所有可执行节（call/jmp）和所有数据节（ptr），并给出结论句：

- `N direct call/jmp site(s)` — 普通函数
- `no direct call/jmp, but the address appears in N data-section slot(s)` — 间接分发，加 `--follow` 找出装载该槽位的代码，那才是真正的调用方
- `no reference of any kind, over every code and data section` — 只有这一句才支持「未被引用」的结论

目标是**数据** → `xrefs-rva`：

```bash
fp binary xrefs-rva target.dll --target 0x1234abcd
fp binary xrefs-rva target.dll --target 0x1234abcd --section .rdata --kinds ptr
fp binary map-refs target.dll --strings "key_a,key_b,key_c"
```

- 范围默认整个 `.text` 节，**不要手动缩小范围**（已两次导致假阴性：240 MB `.text` 上覆盖率 21.8% 和 16.3%，都被读成「没有引用」）
- 检查打印的覆盖率百分比：低于 100% 说明扫描不完整
- `rip` 找不到时试 `--section .rdata --kinds ptr`（表指针）
- 多目标用 `map-refs` 一次扫描，不要循环调用 `xrefs-rva`
- 仍找不到 → 字符串可能是 `movabs` 内联构造（寄存器拼装），用 `fp binary inline-strings`。**不要用 `find-text`**：字符被携带它们的指令操作码切断，任何连续字节搜索都找不到

`xrefs-rva` 现在也不会对这件事保持沉默：对可执行节里的地址得到 0 命中时，它会打印间接分发的解释和应该改跑的 `callers` 命令。

**Step 2b — 内联构造字符串（其他工具的结构性盲区）**

```bash
fp binary inline-strings target.dll --text ConfigValue
fp binary inline-strings target.dll --text ConfigValue --confirmed
fp binary inline-strings target.dll --text 许可过期 --encoding gbk
```

编译器把字符串按 8 字节一组塞进立即数，字符被操作码隔开。`ConfigValue`（11 字节）实际是：

```
48 B8 43 6F 6E 66 69 67 56 61    movabs rax, imm64  -> "ConfigVa"
B8 6C 75 65 00                   mov eax, imm32     -> "lue\0"
```

完整 11 字节在整个文件里**不连续出现**，所以 `find-string-rva` / `find-text` / `search-bytes` 全部返回空；`xrefs-rva` 更没有目标 RVA 可查。只有恰好 8 字节的串能被普通搜索命中——这就是这个盲区长期没暴露的原因。该命令用前 8 字节做锚点，再确认后续分组。

- `opcode` 为 `movabs` 表示锚点确实是 `MOV r64, imm64` 的操作数；为空表示字节匹配但前面没有 MOV 立即数指令（可能是数据），需反汇编确认
- `--confirmed` 只输出前者
- `func_begin_rva` 为 None 很常见：内联构造多出现在没有 `.pdata` 条目的小叶函数里


**Step 2.5 — rip 索引（同一文件要查几十次时才建）**

```bash
fp binary index-build target.dll
fp binary xrefs-rva target.dll --target 0x1234abcd --kinds rip
fp binary index-info target.dll
```

- 单目标查询本身已经不慢：rip 操作数必然是 `ModRM mod=00/rm=101 + disp32`，工具先用字节类正则在 C 层找出可能落到目标的位移，只反汇编含候选的 `.pdata` 函数。251 MB `.text` 全量扫描（覆盖率 100%）**实测 5.6 s**
- **`index-build` 不是首次查询的捷径**：它要记录指向所有数据地址的引用，候选几乎全部命中，等于付掉单目标查询省下的那次全量反汇编（同一文件约 11 分钟）。值不值得取决于后面还要查多少次
- 索引按文件哈希校验：修改过的文件自动回退到实时扫描，且超出索引覆盖范围的查询会回退而不是返回一个看似权威的短列表
- 只缓存 rip 引用；call/jmp/ptr 仍实时扫描

**Step 3 — 收敛到函数（describe → func-bounds → disasm → callees → field-refs）**

```bash
fp binary describe target.dll --rva 0xc43500
fp binary func-bounds target.dll --rva 0xc43500
fp binary disasm-rva target.dll --rva 0xc43500 --count 60
fp binary callees target.dll --rva 0xc43500
fp binary field-refs target.dll --offset 0xB0
```

- `describe` 先把无名函数变成人能读的东西：用函数体引用的字符串起名。DCHECK / NOTREACHED 展开会留下 `__FILE__` 和 `__PRETTY_FUNCTION__`，直方图名也是字面量。**产出依赖构建**：release 版剥掉了大部分 DCHECK，这时只剩普通字符串——实测某 294 MB release chrome.dll 上一个 981 字节函数没有任何源码路径，但拿到 `user-data-dir | sf_cookie.txt | protected-cookiesfile`，已经够认出它了。工具分三类返回，不会把普通串伪装成符号名
- `func-bounds` 从 `.pdata` 取精确边界；返回 None 不代表"不是函数"（叶函数可能没有 .pdata 条目）
- `disasm-rva` ImageBase 正确；rip 目标会带上所在节和目标处的字符串，立即数里的文本也会标出来（`; imm="ConfigVa"`）
- `callees` 是 `callers` 的反方向：该函数调了谁，每个 callee 同样起名。只列直接 `call 0x…`，间接 `call rax` 在指令流里没有名字
- `field-refs` 定位结构体字段读写（如 `this->field_ at +0xB0`）

**偏移不是身份。** `field-refs` 命中上百条时会警告：偏移被无关类共享，这是噪声不是答案（实测某 vtable 槽位偏移在一个 Chromium DLL 里 200+ 处命中）。派发点不知道对象的动态类型，所以过滤不可能把它收窄——这不是工具能修的。走可解的方向：

```bash
fp binary vtable target.dll --target 0x1c43500
```

从**实现地址**反查它在哪个 vtable、第几槽、MSVC RTTI 类名、以及安装该表的构造函数（Chromium 用 `-fno-rtti`，RTTI 为空是正常的，此时构造函数引用是找回类名的唯一路径）。

**Step 4 — 转入动态分析（运行时才有的值）**

当静态分析已定位关键函数但需要运行时数据（加密密钥、协议内容、动态解析的地址）时，切换到 Frida：

```bash
fp attach 1234
fp inject --target YourApp.exe --script hook.js
fp crypto hook-bcrypt --target YourApp.exe
```

**无 `.pdata` 的叶函数，运行期也拿不到调用方。** 两个都实测过：

- `Backtracer.ACCURATE` 走 unwind 信息，对没有 RUNTIME_FUNCTION 条目的叶函数返回空栈或只有一帧
- `this.returnAddress` 因为 Interceptor 的 trampoline，报出的是被 hook 函数自己的地址而不是调用方（实测一个两条指令的 getter，报的就是它自己）

所以 hook 之前先跑 `fp binary func-bounds`；返回 None 就不要指望从运行期栈上认调用方。改用**行为对照**：只改一个输入，数下游函数的调用次数差。生成的 native hook 现在会在 ACCURATE 拿不到栈时回退 `Backtracer.FUZZY`，并在消息里标 `backtracer: accurate | fuzzy`，避免把降级结果当准确结果用。

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
frida_attach              # 附加到进程
frida_spawn               # 启动并附加（挂起状态）
frida_detach              # 断开会话
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
binary_disassemble        # 反汇编（文件偏移，自动检测架构）
binary_find_strings       # 增强字符串提取
binary_search_bytes       # 字节模式搜索（?? 通配符）
binary_xrefs              # 交叉引用查找（文件偏移）
binary_analyze_go         # Go 二进制分析

# ── RVA-aware PE 分析（ImageBase 正确，适用于超大 DLL）──
binary_index_build        # 扫一遍建 rip 引用索引，之后 xrefs 查询变成数据库查询
binary_index_info         # 索引覆盖范围（按文件哈希索引，改过的文件不会命中旧索引）
binary_section_range      # 节的起止 RVA（扫描范围别手填，先问它）

binary_metadata           # 元数据侦察：PDB GUID/符号服务器 key、版本资源、manifest、工具链、Rust 源码路径
binary_find_text          # 同一串按多种编码同时搜（ascii/utf8/utf16le/gbk/big5/cp932/...），返回 RVA
binary_find_string_rva    # 定位字符串并返回 RVA
binary_inline_strings     # 定位 movabs 内联构造的字符串（连续搜索 + xref 的结构性盲区）


binary_xrefs_rva          # RVA 交叉引用（rip 数据引用 + call/jmp，支持 pdata_only）
binary_callers            # 函数调用方：code 节 call/jmp + data 节指针槽位，附结论句
binary_vtable             # 虚函数实现 → vtable/槽号/RTTI 类名/安装该表的构造函数
binary_describe_function  # 用函数体引用的字符串给无名函数起名（源码路径/符号/普通串）
binary_callees            # 该函数调用了谁，每个 callee 同样起名
binary_func_bounds        # 从 .pdata 取函数边界
binary_disasm_rva         # RVA-aware 反汇编（rip/call 目标标注）
binary_field_refs         # 结构体字段 [reg+offset] 读写定位

# ── 加壳检测 ──
unpack_detect             # 识别壳类型（UPX/VMProtect/Themida/ASPack）+ 节熵证据
unpack_auto               # 检测 → 尝试 UPX 脱壳 → 报告后续手段

# ── Android APK/DEX（离线，无需设备）──
apk_analyze               # manifest / 权限 / 组件 / native 库 / 签名 / 保护特征
apk_analyze_dex           # DEX header / 类 / 方法 / 字符串
apk_protections           # Root/SSL pinning/Frida/模拟器检测与加固壳特征（带命中证据）
```

生产级特性：
- **分页**：所有枚举工具支持 offset/limit 分页
- **路径白名单**：`FRIDAPILOT_ALLOWED_DIRS` 限制可分析目录，作用于所有带路径参数的工具
- **审计日志**：所有 MCP 工具调用自动记录
- **标准化响应**：统一 `{success, data, error, duration}` 格式
- **SDK 版本**：使用 MCP 2.x 的 `MCPServer` API（`@mcp.tool()`，schema 由函数签名自动推导），依赖 `mcp>=2.0`



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
- **MCP 标准化**：41 个 MCP 工具，可被 Claude Desktop / Cursor / 任意 Agent 调用




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
