// Node 两段式验证：stage1 与 stage2 分开 write，模拟 HTTP chunk 边界。
// 只验证错误语义/内存破坏，不构造利用。
// 用法: node verify_two_stage.js <file> [stage2_len]
// 说明: 如果进程 SIGSEGV，shell 会看到 rc=139，脚本自身来不及打印 VERDICT。
const fs = require('fs');
const zlib = require('zlib');
const file = process.argv[2];
const stage2Len = parseInt(process.argv[3] || '27', 10);
if (!file) {
  console.error('usage: node verify_two_stage.js <file> [stage2_len]');
  process.exit(2);
}
const all = fs.readFileSync(file);
const s1 = all.subarray(0, all.length - stage2Len);
const s2 = all.subarray(all.length - stage2Len);
console.log('node', process.version, 'file', file, 'stage1', s1.length, 'stage2', s2.length);
const d = zlib.createBrotliDecompress({ chunkSize: 0x330 });
let out = 0;
let verdict = 'unknown';
d.on('data', (b) => { out += b.length; });
d.on('error', (e) => {
  const code = String(e.code || e.errno || '');
  verdict = code.includes('FORMAT_BLOCK_SWITCH') ? 'fixed'
    : (code.includes('Z_BUF_ERROR') ? 'vulnerable-error' : 'error');
  console.log('ERR', code, String(e.message).slice(0, 140));
});
process.on('exit', (c) => {
  if (verdict === 'unknown' && out === 0) verdict = 'silent-empty';
  console.log('VERDICT', verdict, 'exit', c, 'out', out);
});
d.write(s1, () => {
  setTimeout(() => {
    d.write(s2, () => {
      d.end();
      setTimeout(() => { console.log('still alive, out', out); }, 300);
    });
  }, 50);
});
