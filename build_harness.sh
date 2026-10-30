#!/bin/bash
# 编译两段式 C harness：漏洞版 + 修复版，ASAN + 普通。
# 用法: bash build_harness.sh <brotli-1.2.0-src> <brotli-1.2.1-src>
set -e
V120=${1:?usage: $0 <brotli-1.2.0-src> <brotli-1.2.1-src>}
V121=${2:?usage: $0 <brotli-1.2.0-src> <brotli-1.2.1-src>}

build_one() { # src suffix
  SRC=$1
  SUF=$2
  mkdir -p "build-$SUF"
  gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer \
      -I "$SRC/c/include" \
      "$SRC"/c/common/*.c "$SRC"/c/dec/*.c harness_two_stage.c \
      -o "build-$SUF/harness_two_stage_plain_asan" -lm
  gcc -O2 -g \
      -I "$SRC/c/include" \
      "$SRC"/c/common/*.c "$SRC"/c/dec/*.c harness_two_stage.c \
      -o "build-$SUF/harness_two_stage_plain" -lm
  ls -la "build-$SUF"/harness_two_stage_plain*
}

build_one "$V120" v120
build_one "$V121" v121
echo BUILD_DONE
