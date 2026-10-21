// DocuTraceX webcrack runner (Apache-2.0, part of DocuTraceX).
// Reads a JavaScript file and prints its deobfuscated form to stdout using
// webcrack (MIT, provisioned under tools/webcrack/). webcrack evaluates only the
// obfuscation decoder in an isolated-vm sandbox; it never runs the payload's
// effects. Usage: node webcrack_run.js <input.js>
"use strict";
const fs = require("fs");

(async () => {
  try {
    const { webcrack } = require("webcrack");
    const input = process.argv[2];
    if (!input) {
      process.stderr.write("usage: webcrack_run.js <input.js>");
      process.exit(2);
    }
    const code = fs.readFileSync(input, "utf8");
    const result = await webcrack(code);
    process.stdout.write(result.code || "");
  } catch (e) {
    process.stderr.write(String((e && e.message) || e));
    process.exit(3);
  }
})();
