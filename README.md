# repo-sanitizer 🧼

Finds the secrets and hygiene disasters in your repo **before** someone else
does. Read-only by design: it reports and tells you exactly how to fix things,
but never rewrites history or deletes files for you.

**Go edition** — single compiled binary, no runtime needed.

## Usage

```bash
# from source (requires Go 1.22+)
go install github.com/Arch087146/repo-sanitizer@latest

# or grab a prebuilt binary from GitHub Releases
# or build locally
git clone https://github.com/Arch087146/repo-sanitizer && cd repo-sanitizer
go build -o repo-sanitizer .
```

```bash
repo-sanitizer .              # scan tracked + untracked files
repo-sanitizer . --history    # also sweep all of git history (slower)
repo-sanitizer . --json       # CI-friendly output
```

Exits with code **1** on any HIGH-severity finding — drop it straight into CI:

```yaml
- name: secrets check
  run: repo-sanitizer . --history
```

## What it detects

**Secrets (working tree):** AWS access keys, Stripe live keys, GitHub tokens,
Slack tokens, Google API keys, private key blocks, JWTs, hardcoded
`password=`/`api_key=` assignments. Findings are **masked** (`sk_liv…000`) so
the report itself never leaks the value.

**Hygiene:** tracked `.env` files, key material (`.pem`, `id_rsa`), committed
`node_modules`, macOS junk (`.DS_Store`), large binaries.

**`--history`:** the part that actually saves you. Deleting a secret in a new
commit does nothing — it still lives in old commits. The pickaxe sweep
(`git log -G`) finds secrets that exist anywhere in history.

## The one rule

> **Rotate keys FIRST, clean history SECOND.**

If a key touched a public repo, assume bots found it within minutes. Rotating
is the only real fix; `git filter-repo` just removes the evidence.

## Pairs well with

- [`git-regret`](https://github.com/Arch087146/git-regret) — proves your hacks were regrets
- [`repo-roast`](https://github.com/Arch087146/repo-roast) — roasts the rest of your repo

MIT
