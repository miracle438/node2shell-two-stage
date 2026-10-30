#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Python 两段式验证：stage1 与 stage2 分两次 process()，模拟 HTTP chunk 边界。
n=0 表示整包作为 stage1（用于单段对照）。
只验证错误语义/内存破坏，不构造利用。
用法: python3 verify_two_stage.py <file> [stage2_len]
说明: 如果进程 SIGSEGV，shell 会看到 rc=139，脚本自身来不及打印 VERDICT。
"""
import sys
import brotli

if len(sys.argv) < 2:
    print("usage: python3 verify_two_stage.py <file> [stage2_len]")
    sys.exit(2)
path = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 27
data = open(path, "rb").read()
if n == 0:
    s1, s2 = data, b""
else:
    s1, s2 = data[:-n], data[-n:]
print("brotli", getattr(brotli, "__version__", "?"), "stage1", len(s1), "stage2", len(s2))
d = brotli.Decompressor()
verdict = "unknown"
try:
    out1 = d.process(s1)
    print("stage1 returned=%d finished=%s" % (len(out1), d.is_finished()))
    if s2:
        out2 = d.process(s2)
        print("stage2 returned=%d finished=%s" % (len(out2), d.is_finished()))
    else:
        out2 = b""
    total = len(out1) + len(out2)
    print("NO-ERROR total=%d" % total)
    if total == 0 and not d.is_finished():
        verdict = "silent-empty"
    else:
        verdict = "no-error"
except brotli.error as e:
    msg = str(e)
    verdict = "fixed" if "decoder failed" in msg else "vulnerable-error"
    print("ERROR: %s" % msg)
except Exception as e:
    verdict = "error"
    print("EXC: %s %s" % (type(e).__name__, e))
print("VERDICT", verdict)
