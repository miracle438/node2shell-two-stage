// Bun 两段式验证：stage1 与 stage2 分开 write，模拟 HTTP chunk 边界。
// 只验证错误语义/内存破坏，不构造利用。
// 用法: bun verify_two_stage_bun.js <file> [stage2_len]
const fs = require("node:fs");
const zlib = require("node:zlib");
const file = process.argv[2];
const n = parseInt(process.argv[3] || "27", 10);
if (!file) {
  console.error("usage: bun verify_two_stage_bun.js <file> [stage2_len]");
  process.exit(2);
}
const all = fs.readFileSync(file);
const s1 = all.subarray(0, all.length - n);
const s2 = all.subarray(all.length - n);
console.log("bun", Bun.version, "file", file, "stage1", s1.length, "stage2", s2.length);
const d = zlib.createBrotliDecompress({ chunkSize: 0x330 });
let out = 0;
let verdict = "unknown";
d.on("data", (c) => { out += c.length; });
d.on("error", (e) => {
  const code = String(e.code || e.errno || "");
  verdict = code.includes("FORMAT_BLOCK_SWITCH") ? "fixed"
    : (code.includes("Z_BUF_ERROR") ? "vulnerable-error" : "error");
  console.log("ERR", code, String(e.message).slice(0, 140));
});
process.on("exit", (c) => {
  if (verdict === "unknown" && out === 0) verdict = "silent-empty";
  console.log("VERDICT", verdict, "exit", c, "out", out);
});
d.write(s1, () => {
  setTimeout(() => {
    d.write(s2, () => {
      d.end();
      setTimeout(() => { console.log("still alive, out", out); }, 300);
    });
  }, 50);
});
