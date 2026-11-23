"""Repeat every TLC run for this repository and write results/README.md.

Set JAVA to your java and TLA2TOOLS to your tla2tools.jar, then run
    python3 results/run_all.py
from the repository root. Outputs go to results/outputs/, with local paths
replaced by relative ones.
"""
import hashlib, os, re, subprocess, time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL = os.path.join(ROOT, "model")
OUT = os.path.join(ROOT, "results", "outputs")
JAVA = os.environ.get("JAVA", "java")
JAR = os.environ.get("TLA2TOOLS", "tla2tools.jar")
TMP = os.environ.get("TMPDIR", "/tmp").rstrip("/")
INVARIANTS = ["Rule1", "Check3", "RefusedNeverRuns"]
PROPERTIES = ["Rule1Step", "Rule2", "RunNeedsHeldStamp", "CrashRefusesUndecided", "JournalBeforeSend"]
NAMES = {"Rule1": "1 (state form)", "Rule1Step": "1 (step form)", "Rule2": "2", "Check3": "3",
         "RunNeedsHeldStamp": "4", "RefusedNeverRuns": "5", "JournalBeforeSend": "6", "CrashRefusesUndecided": "7"}
WRONG = ["WrongRunBeforeJournal", "WrongRunAfterGivingUp", "WrongWitnessInMemory",
         "WrongFingerprintBeforeJournal", "WrongRunWithoutHeldStamp", "WrongRunAfterRefusal",
         "WrongStampAndRunInOneStep", "WrongWaitsForever"]
os.makedirs(os.path.join(OUT, "matrix"), exist_ok=True)

def clean(text):
    text = text.replace(ROOT + "/", "").replace(ROOT, ".")
    text = re.sub(re.escape(TMP) + r"[^\s]*/", "<tmp>/", text)
    return re.sub(r"(/private)?/(var/folders|tmp)/[^\s]*/", "<tmp>/", text)

def tlc(spec, cfg, name, extra=(), sub=""):
    cmd = [JAVA, "-Djava.io.tmpdir=" + TMP, "-DTLA-Library=" + MODEL, "-cp", JAR, "tlc2.TLC",
           "-workers", "auto", "-metadir", os.path.join(TMP, "tlc_spike", name), *extra, "-config", cfg, spec]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=MODEL, capture_output=True, text=True)
    text = clean(r.stdout + r.stderr)
    open(os.path.join(OUT, sub, name + ".txt"), "w").write(text)
    return text, time.time() - t0

def verdict(text):
    if "No error has been found" in text:
        return "holds"
    if re.search(r"(Invariant|Action property) \w+ is violated", text) or "Temporal properties were violated" in text:
        return "broken"
    return "deadlock" if "Deadlock reached" in text else "error"

def final(text):
    m = re.search(r"([\d,]+) states generated, ([\d,]+) distinct states found, 0 states left on queue", text)
    d = re.search(r"depth of the complete state graph search is (\d+)", text)
    counts = (int(m.group(1).replace(",", "")), int(m.group(2).replace(",", ""))) if m else (None, None)
    return counts, (d.group(1) if d else "-")

def trace(text):
    return len(re.findall(r"^State \d+:", text, re.M))

def cfg_head(path):
    keep, mode = [], None
    for ln in open(path).read().splitlines():
        s = ln.strip()
        if not s or s.startswith("\\*"):
            continue
        if s in ("SPECIFICATION", "CONSTANTS"):
            mode = s; keep.append(s); continue
        if s in ("INVARIANTS", "PROPERTIES", "INVARIANT", "PROPERTY"):
            mode = None; continue
        if mode:
            keep.append("    " + s)
    return "\n".join(keep)

main = []
for label, name, spec, cfg, extra in [
        ("The spec, three tool calls, all checks, deadlock check on", "1_Gate", "Gate.tla", "Gate.cfg", ()),
        ("The spec, four tool calls, all checks", "2_Gate_4calls", "Gate.tla", os.path.join(ROOT, "results", "Gate_4actions.cfg"), ()),
        ("The two-call model, check 8", "3_GateLive", "GateLive.tla", "GateLive.cfg", ()),
        ("The version that waits forever, check 8, with -deadlock", "4_WrongWaitsForever_liveness", "wrong/WrongWaitsForever.tla", "wrong/WrongWaitsForever.cfg", ("-deadlock",)),
        ("Reachability: no call ever starts (must break)", "5_GateReach", os.path.join(ROOT, "results", "GateReach.tla"), os.path.join(ROOT, "results", "GateReach.cfg"), ("-workers", "1"))]:
    if extra[:1] == ("-workers",):
        extra = ()
    text, secs = tlc(spec, cfg, name, extra)
    (gen, dist), depth = final(text)
    main.append((label, name, verdict(text), gen, dist, depth, trace(text), round(secs)))
    print(name, verdict(text), dist, flush=True)

rows = []
for w in WRONG:
    head = cfg_head(os.path.join(MODEL, "wrong", w + ".cfg"))
    cells = {}
    for c in INVARIANTS + PROPERTIES:
        path = os.path.join(TMP, "tlc_spike_cfg", w + "__" + c + ".cfg")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        body = head + "\nINVARIANTS\n    TypeOK\n"
        body += ("    " + c + "\n") if c in INVARIANTS else ("PROPERTIES\n    " + c + "\n")
        open(path, "w").write(body)
        text, _ = tlc("wrong/" + w + ".tla", path, w + "__" + c, ("-deadlock",), "matrix")
        v = verdict(text)
        cells[c] = ("broken (%d states)" % trace(text)) if v == "broken" else v
    rows.append((w, cells))
    print(w, [cells[c] for c in INVARIANTS + PROPERTIES], flush=True)

def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

inputs = sorted(os.path.relpath(os.path.join(dp, f), ROOT) for dp, _, fs in os.walk(MODEL) for f in fs if f.endswith((".tla", ".cfg")))
inputs += ["results/GateReach.tla", "results/GateReach.cfg", "results/Gate_4actions.cfg", "results/run_all.py"]
order = ["Rule1", "Rule1Step", "Rule2", "Check3", "RunNeedsHeldStamp", "RefusedNeverRuns", "JournalBeforeSend", "CrashRefusesUndecided"]
lines = ["# Results", "",
         "Written by `results/run_all.py`, which ran every check below and saved TLC's outputs in `results/outputs/`.", "",
         "## Main runs", "", "| Run | TLC's verdict | Distinct states | States generated | Search depth | Trace length | Output |",
         "|---|---|---|---|---|---|---|"]
for label, name, v, gen, dist, depth, tr, secs in main:
    lines.append("| %s | %s | %s | %s | %s | %s | `outputs/%s.txt` |" % (
        label, v, "{:,}".format(dist) if dist else "-", "{:,}".format(gen) if gen else "-", depth, tr if tr else "-", name))
lines += ["", "## Each broken version against each check alone", "",
          "One TLC run per cell, with `TypeOK` and that one check, deadlock reporting off. Check numbers are those of the top-level README. "
          "\"broken (n states)\" gives the length of TLC's trace; \"holds\" means TLC searched every reachable state and the check held.", "",
          "| Broken version | " + " | ".join(NAMES[c] for c in order) + " |", "|---" * (1 + len(order)) + "|"]
for w, cells in rows:
    lines.append("| %s | %s |" % (w, " | ".join(cells[c] for c in order)))
lines += ["", "## Fingerprints of the files checked (sha256)", "", "```"] + \
         ["%s  %s" % (sha(os.path.join(ROOT, p)), p) for p in inputs] + ["```", ""]
open(os.path.join(ROOT, "results", "README.md"), "w").write("\n".join(lines))
print("done")
