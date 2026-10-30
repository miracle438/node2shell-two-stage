/* harness_two_stage.c —— 只验证 CVE-2026-111497 的状态覆盖路径，不构造利用。
 * 用法: harness_two_stage <file> <stage2_len> <in_chunk> <out_chunk>
 *  第一阶段：按 in_chunk 推进输入，输出缓冲 out_chunk，NEEDS_MORE_OUTPUT 时
 *            保留输入游标继续排空，直到 stage1 全部喂完。
 *  第二阶段：stage2 额外按 1 字节/次喂入（触发内部 8 字节缓冲的追加路径），
 *            之后再用 4 个填充字节尝试让解码器带着被覆盖的状态继续。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/decode.h>

static const char* rname(BrotliDecoderResult r) {
  switch (r) {
    case BROTLI_DECODER_RESULT_ERROR: return "ERROR";
    case BROTLI_DECODER_RESULT_SUCCESS: return "SUCCESS";
    case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: return "NEEDS_MORE_INPUT";
    case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: return "NEEDS_MORE_OUTPUT";
    default: return "?";
  }
}

typedef struct {
  BrotliDecoderState* st;
  const unsigned char* base;
  const unsigned char* cur;
  const unsigned char* end;
  unsigned char* out;
  size_t out_cap;
  unsigned long calls;
} Ctx;

static BrotliDecoderResult step(Ctx* c, size_t in_len, const char* tag, int verbose) {
  size_t avail_in = in_len, avail_out = c->out_cap, total_out = 0;
  const unsigned char* next_in = c->cur;
  unsigned char* next_out = c->out;
  BrotliDecoderResult r = BrotliDecoderDecompressStream(
      c->st, &avail_in, &next_in, &avail_out, &next_out, &total_out);
  size_t consumed = (size_t)(next_in - c->cur);
  c->cur += consumed;
  c->calls++;
  if (verbose || c->calls < 6 || r == BROTLI_DECODER_RESULT_ERROR) {
    fprintf(stderr,
            "[CALL %s #%lu] in=%zu consumed=%zu left_in=%zu out=%zu left_out=%zu total=%zu -> %s code=%d\n",
            tag, c->calls, in_len, consumed, avail_in, c->out_cap, avail_out,
            total_out, rname(r), (int)BrotliDecoderGetErrorCode(c->st));
  }
  return r;
}

int main(int argc, char** argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: %s <file> <stage2_len> <in_chunk> <out_chunk>\n", argv[0]);
    return 1;
  }
  const char* path = argv[1];
  size_t stage2_len = (size_t)strtoul(argv[2], NULL, 0);
  size_t in_chunk = (size_t)strtoul(argv[3], NULL, 0);
  size_t out_chunk = (size_t)strtoul(argv[4], NULL, 0);
  FILE* f = fopen(path, "rb");
  if (!f) { perror("open"); return 1; }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char* in = (unsigned char*)malloc((size_t)n);
  if (fread(in, 1, (size_t)n, f) != (size_t)n) { perror("read"); return 1; }
  fclose(f);
  if ((size_t)n < stage2_len) { fprintf(stderr, "file too small\n"); return 1; }

  Ctx c;
  c.st = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  c.base = in;
  c.cur = in;
  c.out = (unsigned char*)malloc(out_chunk);
  c.out_cap = out_chunk;
  c.calls = 0;
  size_t stage1_len = (size_t)n - stage2_len;
  c.end = in + stage1_len;
  fprintf(stderr, "[INFO] file=%s total=%ld stage1=%zu stage2=%zu in_chunk=%zu out_chunk=%zu\n",
          path, n, stage1_len, stage2_len, in_chunk, out_chunk);

  /* 阶段一：推进 stage1，处理 NEEDS_MORE_OUTPUT。 */
  while (c.cur < c.end) {
    size_t remain = (size_t)(c.end - c.cur);
    size_t give = remain < in_chunk ? remain : in_chunk;
    BrotliDecoderResult r = step(&c, give, "s1", (c.calls < 6));
    if (r == BROTLI_DECODER_RESULT_ERROR || r == BROTLI_DECODER_RESULT_SUCCESS) break;
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && c.cur < c.end) continue;
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue;
  }
  fprintf(stderr, "[INFO] stage1 done: cur_off=%ld left=%ld\n",
          (long)(c.cur - c.base), (long)(c.end - c.cur));

  /* 阶段二：逐字节喂 stage2。 */
  c.end = in + (size_t)n;
  while (c.cur < c.end) {
    BrotliDecoderResult r = step(&c, 1, "s2", 1);
    if (r == BROTLI_DECODER_RESULT_ERROR || r == BROTLI_DECODER_RESULT_SUCCESS) break;
  }
  fprintf(stderr, "[INFO] stage2 done: cur_off=%ld\n", (long)(c.cur - c.base));

  /* 填充：让解码器带着可能被覆盖的状态再跑几次。 */
  static const unsigned char filler[4] = {0, 0, 0, 0};
  for (int i = 0; i < 4; i++) {
    c.cur = filler + i;
    BrotliDecoderResult r = step(&c, 1, "fill", 1);
    if (r == BROTLI_DECODER_RESULT_ERROR || r == BROTLI_DECODER_RESULT_SUCCESS) break;
  }
  BrotliDecoderDestroyInstance(c.st);
  free(c.out);
  free(in);
  return 0;
}
