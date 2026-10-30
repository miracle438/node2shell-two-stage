# node2shell two-stage harness

CVE-2026-111497（node2shell）的两段式本地验证工具。它生成公开 PoC 结构的完整流，分别喂给纯 C 的 Brotli 解码器、Node、Bun 和 Python，记录错误语义或内存破坏。

**范围**：只验证触发行为、错误语义和内存破坏，不包含 RCE、ROP、回调或武器化内容；只在隔离虚拟机/本地文件/127.0.0.1 使用。

## 背景

Node.js 2026 年 10 月安全批次里的 Brotli 越界写。公开 PoC 把攻击流拆成两个 HTTP chunk：

- stage one：23,069,720 字节，负责耗尽距离块计数、制造“不可能的块切换”；
- stage two：27 字节（poison）或 127 字节（groom），继续同一个比特流，覆盖解码器状态。

只喂 stage one 时，纯 C ASAN 和裸 Node 都是干净的；补上 stage two 才会出现写。这个仓库把两段流的生成、C 层裁决和各运行时验证整理成可复现脚本。

## 快速开始

### 1. 生成流

```bash
python3 gen_rce_full.py
```

输出 `groom_full.bro` 和 `poison_full.bro`（各约 23MB），并打印 SHA256 前缀。流来自公开 PoC `dimasma0305/CVE-2026-111497-POC` 的 `generate_stream` / `rce_stage_one` / `rce_stage_two`，proof payload 换成了无执行语义的模式数据。

### 2. 编译 C harness

需要 brotli 1.2.0（漏洞）和 1.2.1（修复）源码：

```bash
bash build_harness.sh /path/to/brotli-1.2.0 /path/to/brotli-1.2.1
```

产物：

- `build-v120/harness_two_stage_plain_asan`
- `build-v120/harness_two_stage_plain`
- `build-v121/harness_two_stage_plain_asan`
- `build-v121/harness_two_stage_plain`

### 3. 运行

```bash
# 漏洞版：预期 SEGV（memmove16 野写）
ASAN_OPTIONS=detect_leaks=0 ./build-v120/harness_two_stage_plain_asan poison_full.bro 27 16384 0x330

# 修复版：预期 ERROR code=-17
ASAN_OPTIONS=detect_leaks=0 ./build-v121/harness_two_stage_plain_asan poison_full.bro 27 16384 0x330
```

参数：`<file> <stage2_len> <in_chunk> <out_chunk>`。

Node / Bun / Python：

```bash
node verify_two_stage.js poison_full.bro 27
bun verify_two_stage_bun.js poison_full.bro 27
python3 verify_two_stage.py poison_full.bro 27
```

单段对照：用 `poison_stream.bro`（只有 stage one）并传 `0`：

```bash
node verify_two_stage.js poison_stream.bro 0
python3 verify_two_stage.py poison_stream.bro 0
```

## 预期结果（2026-10-30，Ubuntu 24.04 x86_64）

| 运行时 | 版本 | 单段 | 两段 poison 27B |
|---|---|---|---|
| brotli C ASAN | 1.2.0 | 干净，NEEDS_MORE_INPUT | **SEGV in memmove16（写）** |
| brotli C | 1.2.1 | -17 | -17 |
| Node.js | 24.22.0 | 干净 | **SIGSEGV，rc=139** |
| Node.js | 24.22.1 | -17 | -17 |
| Bun | 1.4.3 | Z_BUF_ERROR，存活 | Z_BUF_ERROR，存活（out 2048） |
| Bun | 1.4.4 | -17 | -17 |
| Python brotli | 1.1.0 | 静默，1024B，is_finished=False | **SIGSEGV，rc=139** |
| Python brotli | 1.2.1 | 报错 | 报错（decoder failed） |

Bun 在两段流下没有崩溃，但错误语义仍然是漏洞版的 Z_BUF_ERROR；Python 1.1.0 会直接段错误。两者都说明触发键是第二段对共享 C 库状态的覆盖，具体表现取决于绑定的分配/错误处理。

## 文件

```
gen_rce_full.py            # 两段式流生成器
harness_two_stage.c        # C 层两段式喂入装置
build_harness.sh           # 编译漏洞版/修复版 harness
verify_two_stage.js        # Node 验证脚本
verify_two_stage_bun.js    # Bun 验证脚本
verify_two_stage.py        # Python 验证脚本
data/
├── stage2_trace.txt       # 逐字节 APPEND/STATE 日志
├── stage2_len_sweep.txt   # 第二段长度 N 扫描
├── copy_trace_matrix.txt  # 写地址/环绕次数矩阵
├── two_stage_c_controls.txt
├── two_stage_node_controls.txt
└── two_stage_bun_py.txt
```

## 关键结论

- `BrotliDecoderState.buffer.u8` 是 8 字节；无效块切换被当成 NEEDS_MORE_INPUT 后，第二段逐字节追加，`buffer_length` 被自己覆盖后写穿 `pos`、`max_backward_distance`、`max_distance`。
- 27 字节加 stage one 末尾 1 字节尾随，正好覆盖到 `max_distance` 末尾；N≥23 才能抬升 `max_backward_distance`，让距离检查进入 LZ77 复制路径。
- 写地址 = `ringbuffer + staged_pos − N×1024`；N 由输出排空节奏决定（0x330→8，≥0x1000→20，公开 PoC express→10，即 0x2800）。
- 修复版 1.2.1 在无效块切换处返回 -17，不进入追加循环。

## 数据来源与声明

- 触发流结构来自公开 PoC：https://github.com/dimasma0305/CVE-2026-111497-POC
- Node.js 安全公告：https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
- 上位文章（待发布）：`实战｜补上 27 字节，node2shell 的越界写就出现了`
- 原始数据在 2026-10-30 的隔离 VM 上采集；ASLR 地址每次运行会变，`data/` 里的地址只用于对照同一次运行的 `pos`/`ringbuffer` 关系。
- 这不是通用检测器，也不是利用工具；不要用于未授权目标。

## License

MIT
