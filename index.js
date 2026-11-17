#!/usr/bin/env node
/*
 * repo-sanitizer — scans a repo for leaked secrets and hygiene disasters.
 * v1 policy: READ-ONLY. It reports and tells you how to fix things; it never
 * rewrites history or deletes files by itself (that's how you lose weekends).
 *
 *   node index.js            scan tracked + untracked files at HEAD
 *   node index.js --history  additionally sweep all of git history (slower)
 *   node index.js --json     machine-readable findings
 *
 * Exit code 1 if any HIGH severity finding — CI-friendly.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

/* ---------- ANSI ---------- */
const c = (code, s) => `\x1b[${code}m${s}\x1b[0m`;
const bold = (s) => c("1", s);
const dim = (s) => c("2", s);
const red = (s) => c("31", s);
const yellow = (s) => c("33", s);
const green = (s) => c("32", s);

/* ---------- secret patterns ---------- */
// mask(): show just enough to recognize the finding without leaking it.
const mask = (s) => (s.length > 10 ? s.slice(0, 6) + "…" + s.slice(-3) : s);

const PATTERNS = [
  { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, sev: "HIGH", fix: "Rotate the key in AWS IAM immediately, then remove from history." },
  { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, sev: "HIGH", fix: "That's a private key. Rotate it and remove from history with git filter-repo." },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, sev: "HIGH", fix: "Revoke the token at api.slack.com, then purge from history." },
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/g, sev: "HIGH", fix: "Restrict/regenerate in Google Cloud console, then purge from history." },
  { name: "Stripe secret key", re: /sk_live_[A-Za-z0-9]{16,}/g, sev: "HIGH", fix: "Rotate in Stripe dashboard, then purge from history." },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{30,}/g, sev: "HIGH", fix: "Revoke at github.com/settings/tokens, then purge from history." },
  { name: "JWT", re: /eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, sev: "MED", fix: "JWTs in source are usually test artifacts — confirm and remove." },
  { name: "Hardcoded credential", re: /(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["'][^"'\s]{8,}["']/gi, sev: "MED", fix: "Move to environment variables or a secret manager. Check it's not a real credential." },
];

/* ---------- hygiene file checks ---------- */
const FILE_CHECKS = [
  { test: (f) => /^\.env(\..+)?$/i.test(path.basename(f)), sev: "HIGH", why: ".env file in git — likely contains real secrets" },
  { test: (f) => /\.(pem|key|pfx|p12)$/i.test(f) || /(^|\/)id_rsa/i.test(f), sev: "HIGH", why: "key material tracked in git" },
  { test: (f) => /(^|\/)node_modules\//.test(f), sev: "MED", why: "node_modules committed — 100MB of regret" },
  { test: (f) => /(^|\/)\.DS_Store$/.test(f), sev: "LOW", why: "macOS junk file" },
  { test: (f) => /\.(mp4|mov|zip|tar|gz|iso|dmg)$/i.test(f), sev: "LOW", why: "large binary tracked in git" },
];

/* ---------- scanning ---------- */
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "__pycache__"]);

function listFiles(root) {
  let out = [];
  try {
    const tracked = execFileSync("git", ["ls-files"], { encoding: "utf8", cwd: root }).split("\n").filter(Boolean);
    const others = execFileSync("git", ["ls-files", "--others", "--exclude-standard"], { encoding: "utf8", cwd: root }).split("\n").filter(Boolean);
    out = [...tracked, ...others];
  } catch {
    console.error(red("✗ Not a git repository."));
    process.exit(1);
  }
  return out.filter((f) => !f.split("/").some((p) => SKIP_DIRS.has(p)));
}

function scanFiles(root, files) {
  const findings = [];
  for (const rel of files) {
    const abs = path.join(root, rel);
    let text = null;
    try {
      text = fs.readFileSync(abs, "utf8");
    } catch { continue; }

    // hygiene checks by path
    for (const check of FILE_CHECKS) {
      if (check.test(rel)) {
        findings.push({ sev: check.sev, type: check.why, where: rel, sample: "", fix: suggestFor(check.why) });
      }
    }

    // secret patterns by content
    for (const p of PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags);
      let m;
      while ((m = re.exec(text))) {
        const line = text.slice(0, m.index).split("\n").length;
        findings.push({ sev: p.sev, type: p.name, where: `${rel}:${line}`, sample: mask(m[0]), fix: p.fix });
      }
    }
  }
  return findings;
}

function suggestFor(why) {
  if (why.includes(".env")) return "git rm --cached .env, add to .gitignore, rotate any keys inside it.";
  if (why.includes("key material")) return "Remove and rotate. If it's a deploy key, generate a fresh one.";
  if (why.includes("node_modules")) return "git rm -r --cached node_modules, add to .gitignore. The lockfile is enough.";
  if (why.includes("junk")) return "Add .DS_Store to .gitignore and git rm --cached it.";
  return "Add to .gitignore or use Git LFS for binaries.";
}

function scanHistory(root) {
  // Pickaxe sweep per high-signal pattern. Slow, but history lies don't age out.
  const hits = [];
  const reSources = [
    { name: "AWS Access Key ID", src: "AKIA[0-9A-Z]{16}" },
    { name: "Private key block", src: "-----BEGIN [A-Z ]*PRIVATE KEY" },
    { name: "Slack token", src: "xox[baprs]-[A-Za-z0-9-]{10,}" },
    { name: "GitHub token", src: "gh[pousr]_[A-Za-z0-9]{30,}" },
  ];
  for (const p of reSources) {
    try {
      const out = execFileSync("git", ["log", "--all", "--oneline", `-G${p.src}`], { encoding: "utf8", cwd: root });
      const commits = out.split("\n").filter(Boolean);
      if (commits.length) {
        hits.push({ type: p.name + " (in git history)", commits: commits.length, example: commits[0].trim() });
      }
    } catch { /* pattern not present → git exits empty */ }
  }
  return hits;
}

/* ---------- output ---------- */
function report(files, findings, historyHits, json) {
  if (json) {
    console.log(JSON.stringify({ filesScanned: files.length, findings, historyHits }, null, 2));
    return findings.some((f) => f.sev === "HIGH") ? 1 : 0;
  }

  console.log();
  console.log(bold("  🧼 repo-sanitizer"));
  console.log(dim(`  scanned ${files.length} tracked/untracked files`));
  console.log();

  if (findings.length === 0 && historyHits.length === 0) {
    console.log(green("  ✔ Clean. No secrets, no junk. Your future self says thanks."));
    console.log();
    return 0;
  }

  const order = { HIGH: 0, MED: 1, LOW: 2 };
  findings.sort((a, b) => order[a.sev] - order[b.sev]);
  for (const f of findings) {
    const tag = f.sev === "HIGH" ? red("[HIGH] ") : f.sev === "MED" ? yellow("[MED ] ") : dim("[LOW ] ");
    console.log(`  ${tag}${bold(f.type)} — ${f.where}${f.sample ? dim(`  (${f.sample})`) : ""}`);
    console.log(`        ${dim("fix: " + f.fix)}`);
  }

  for (const h of historyHits) {
    console.log(`  ${red("[HIGH] ")}${bold(h.type)}`);
    console.log(`        ${dim(`present in ${h.commits} historical commit(s), e.g. ${h.example}`)}`);
    console.log(`        ${dim("fix: deleting the file now does NOT remove it from history — use git filter-repo, then rotate every exposed key.")}`);
  }

  console.log();
  const highs = findings.filter((f) => f.sev === "HIGH").length + historyHits.length;
  console.log(bold(highs > 0 ? `  ${red(`${highs} high-severity finding(s). Rotate keys FIRST, clean history SECOND.`)}` : "  No high-severity findings. Mild embarrassment only."));
  console.log();
  return highs > 0 ? 1 : 0;
}

function main() {
  const argv = process.argv.slice(2);
  const dirArg = argv.find((a) => !a.startsWith("--"));
  const root = path.resolve(dirArg || process.cwd());

  const files = listFiles(root);
  const findings = scanFiles(root, files);
  const historyHits = argv.includes("--history") ? scanHistory(root) : [];

  process.exitCode = report(files, findings, historyHits, argv.includes("--json"));
}

main();
