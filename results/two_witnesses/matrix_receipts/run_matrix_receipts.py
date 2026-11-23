"""Each wrong version of GateBothWitnesses against each of its checks on its own.

The same method as the one-witness model's table:
one TLC run per (wrong version, check), with TypeOK and that one check,
deadlock reporting off, so that "which checks break" is an observed result
for every pair. Wrong versions are every model/wrong/WrongBoth*.tla.
Env: JAVA (default: java), TLA2TOOLS (default: tla2tools.jar).
"""
import glob, os, re, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.abspath(os.path.join(HERE, "..", "..", "..", "model"))
JAVA = os.environ.get("JAVA", "java")
JAR = os.environ.get("TLA2TOOLS", "tla2tools.jar")
TMP = os.environ.get("TMPDIR", "/tmp")
INVARIANTS = ["Rule1", "Check3", "RefusedNeverRuns", "StampsOnlyFromAsked", "BothListsHoldStarted", "BothReceiptsHeld"]
PROPERTIES = ["Rule1Step", "Rule2", "RunNeedsHeldStamp", "CrashRefusesUndecided", "JournalBeforeSend"]
WRONG = sorted(os.path.basename(p)[:-4] for p in glob.glob(MODEL + "/wrong/WrongBoth*.tla")
               if not p.endswith("WrongBothNoResendFairness.tla"))  # liveness-only; run on its own
os.makedirs(HERE + "/outputs", exist_ok=True)


def tlc(spec, cfg, out):
    cmd = [JAVA, "-Djava.io.tmpdir=" + TMP, "-DTLA-Library=" + MODEL, "-cp", JAR, "tlc2.TLC",
           "-workers", os.environ.get("WORKERS", "auto"), "-metadir", os.path.join(TMP, "tlc_mb", os.path.basename(out)),
           "-deadlock", "-config", cfg, spec]
    t0 = time.time()
    r = subprocess.run(cmd, cwd=MODEL, capture_output=True, text=True)
    text = (r.stdout + r.stderr).replace(MODEL + "/", "").replace(TMP, "$TMPDIR")
    open(out, "w").write(text)
    return text, time.time() - t0

def verdict(text):
    if "No error has been found" in text:
        return "holds"
    if re.search(r"(Invariant|Action property) (\w+) is violated", text) or "Temporal properties were violated" in text:
        return "broken"
    if "Deadlock reached" in text:
        return "deadlock"
    return "error"

def head(cfgfile):
    keep, mode = [], None
    for ln in open(cfgfile).read().splitlines():
        s = ln.strip()
        if s.startswith("\\*") or not s:
            continue
        if s in ("SPECIFICATION", "CONSTANTS"):
            mode = s; keep.append(s); continue
        if s in ("INVARIANTS", "PROPERTIES", "INVARIANT", "PROPERTY"):
            mode = None; continue
        if mode:
            keep.append("    " + s)
    return "\n".join(keep)

rows, t_all, reused = [], time.time(), 0
for w in WRONG:
    base = head(MODEL + "/wrong/" + w + ".cfg")
    row = [w]
    for c in INVARIANTS + PROPERTIES:
        cfg = os.path.join(TMP, "tlc_mb_cfg", w + "__" + c + ".cfg")
        os.makedirs(os.path.dirname(cfg), exist_ok=True)
        body = base + "\nINVARIANTS\n    TypeOK\n"
        body += ("    " + c + "\n") if c in INVARIANTS else ("PROPERTIES\n    " + c + "\n")
        open(cfg, "w").write(body)
        out = HERE + "/outputs/" + w + "__" + c + ".txt"
        if os.path.exists(out) and verdict(open(out).read()) != "error":  # reuse a finished result
            text, secs = open(out).read(), 0.0; reused += 1
        else:
            text, secs = tlc("wrong/" + w + ".tla", cfg, out)
        v = verdict(text)
        t = len(re.findall(r"^State \d+:", text, re.M))
        row.append("BROKEN (%d)" % t if v == "broken" else v)
        print(w, c, row[-1], "%.0fs" % secs, flush=True)
    rows.append(row)

if reused == len(rows) * len(INVARIANTS + PROPERTIES):
    print("every cell was done by an earlier run; matrix.md kept"); raise SystemExit
hdr = "| Wrong version | " + " | ".join(INVARIANTS + PROPERTIES) + " |"
sep = "|---" * (1 + len(INVARIANTS + PROPERTIES)) + "|"
open(HERE + "/matrix.md", "w").write(
    "# GateBothWitnesses (with late receipts and re-stamping): each wrong version against each check alone\n\n"
    "Each cell is one TLC run with TypeOK and that one check, deadlock reporting off, two calls. "
    "BROKEN (n) means the check broke, with a trace of n states; holds means TLC searched every "
    "reachable state and the check held. Total time: %.0f minutes.\n\n" % ((time.time() - t_all) / 60)
    + "\n".join([hdr, sep] + ["| " + " | ".join(r) + " |" for r in rows]) + "\n")
print("done")
