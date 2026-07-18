# INtrack Dashboard
### A local web UI for INtrack — built on top of the CLI, not a replacement for it

---

## Why this exists

INtrack does the real work — instance detection, vuln scanning, IoT fingerprinting, exposure checks, the whole scanner core. That's not changing, and it's not being touched.

What was missing was a way to run it without memorizing flags every time, watch a scan happen in real time instead of staring at a scrollback buffer, and actually keep a history of what's been scanned instead of losing it the second the terminal closes.

So: a dashboard. Local only, wraps the real `intrack` binary as a subprocess, and every single thing it does maps to a real CLI flag. Nothing about the tool's actual behavior changed — this is a skin with memory, not a rewrite.

---

## The core design decision

The dashboard doesn't import INtrack's Python functions directly. It shells out to the actual `intrack` command, the same way you'd type it yourself.

That was deliberate, for a few reasons:

- **Proxychains only makes sense this way.** Routing a scan through a proxy means wrapping the whole process (`proxychains4 intrack ...`), which isn't something you can toggle mid-process if you're importing functions in-process. Shelling out makes it a one-line prepend.
- **The CLI and the UI can never drift apart.** Since the dashboard builds the exact argv string the CLI expects, "UI Mode" and "CLI Mode" always agree — there's no separate code path that could silently diverge from what the CLI actually does.
- **You can keep developing the scanner independently.** New scanner module, new flag, whatever — as long as it's exposed on the CLI, the dashboard doesn't need a rewrite to support it. `Scanner List` even pulls `intrack --list` live so it reflects whatever's actually installed.

---

## Walkthrough

### Dashboard (the main scan console)

This is where a scan actually gets configured and launched.

**Target Configuration** — three modes, chip-selectable:
- Host / Subnet → maps to `-H`
- File → maps to `-f`, point it at a target list
- Random N → maps to `-n`, pull a random sample of targets

**Scan parameters** — port(s), threads, timeout, bar style, output file. All standard CLI flags, just in form fields instead of typed out.

**Scanner Type** — a grid of all eight scan types (instance, vuln, iot, exposure, backdoor, network, worm, probe). Click one, type the scan value (e.g. `wordpress`), or leave it blank for `--probe`.

**Toggles:**
- *Proxychains* — off by default, on prepends `proxychains4` to whatever command actually runs
- *Resolve Hostnames* — wires up `--hostname`, which wasn't exposed in any UI before this

**Live Output** — this isn't a mockup console. It's a real Server-Sent Events stream from the subprocess's actual stdout, so what you see is exactly what the terminal would show, just rendered in the browser as it happens.

### UI Mode / CLI Mode

Toggle at the top of the Dashboard. Flip to CLI Mode and it shows the *exact* command that UI Mode would run — live, updating as you change fields. Copy button included.

The point: you're never locked into the UI. Configure visually, copy the command, run it yourself in a terminal if you want to. Or just run it straight from the browser. Same result either way, since it's the same underlying command.

### Scanner List

Pulls `intrack --list` on demand and renders the raw output. No hardcoded scanner names anywhere in the dashboard — if a scanner module gets added or removed from INtrack itself, this reflects it automatically on next load.

### Past Results

Every scan run through the dashboard gets written to SQLite: the exact command, status (running / completed / failed / stopped), start and end time, and a findings count parsed from the output. Click any row to see the full raw output from that run. Delete button for cleanup.

This is the thing that was missing most from raw CLI use — a scan history that survives closing the terminal.

### Exports

If a scan used `-o` to write results to a file, it shows up here with a real download link — reads straight off disk, so if the file's been moved or deleted it'll say so honestly instead of pretending it exists.

### Targets

Save a host/subnet or file path under a name (e.g. "Home Lab" → `192.168.1.0/24`). One click loads it straight into the Dashboard's target field. Useful for anything scanned repeatedly.

### Settings

Persisted defaults — threads, timeout, bar style, proxychains state, default scanner type — stored in SQLite so they survive a restart and prefill the Dashboard form automatically.

---

## Under the hood

```
Browser (index.html)
      │
      ▼
Flask backend (app.py)
      │  builds argv from form config
      │  launches subprocess
      ▼
intrack CLI  ──▶  real scanner package (unchanged)
      │
      ▼
stdout streamed back live via SSE
```

- **`app.py`** — the Flask layer. Roughly a dozen routes covering scan lifecycle (`/api/scan/start`, `/api/scan/<id>/stream`, `/api/scan/<id>/stop`), history, exports, targets, and settings. No scanning logic lives here — it's argv construction and subprocess management.
- **`db.py`** — SQLite persistence for scans, targets, and settings. Three tables, no external database dependency.
- **`static/index.html`** — the entire frontend in one file. Vanilla JS, no build step, no framework — open it, it just works.

Install is `pip install -e .` from the repo root (points the `intrack` command at the local source, so `git pull` updates take effect immediately) plus `pip install -r requirements.txt` inside `webui/`. Full steps and troubleshooting in `INSTALL.md`.

---

## What it's not (yet)

Being straight about the current gaps rather than overselling it:

- **No structured scan output.** INtrack's output is colored terminal text, not JSON, so the results table on a running scan does a best-effort regex parse for `[+]` lines rather than a clean structured feed. A `--json` output mode on the CLI side would fix this properly — worth a conversation if it's something worth building.
- **Single-user, local-only.** No auth layer. Fine for localhost use, not something to expose on a network as-is.
- **In-memory scan tracking during a run** — history persists after completion, but if the Flask process itself gets killed mid-scan, that scan's live state is lost (though the subprocess and its output up to that point aren't).

None of these are hard blockers, just the honest list of what's next if this becomes the primary way INtrack gets used.
