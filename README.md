# A witnessed gate for an AI agent's tool calls: first spike

If the only record of an AI agent's test comes from whoever ran it, an outsider has to trust that record. I'm working on how such records can be audited and trusted, and on how formal methods can help. This repository is a first small step. It checks one thing an outsider's audit would need, in a model of one design at small sizes: no tool call can start until a separate witness has recorded its fingerprint. The design puts the witness outside the operator's control, and the model takes the witness's honesty as given. A second step, added on 23 November 2026, puts the design into code: a gate for Inspect, and a checker that reads the records afterwards (see "The code").

The model is written in TLA+, a language for describing step by step how a system can behave. It is checked with TLC, the TLA+ model checker. TLC tries every order of events that a small version of the description allows, and reports any order that breaks a stated check.

## The design

Before a tool call starts (say, "delete notes.txt"), the gate writes it in a journal. It then sends the witness a fingerprint of the entry, a short code that identifies it, and waits for the witness's stamp, its answer naming that fingerprint. Only then does the call start. While waiting, the gate may give up and write a refusal, even if the stamp has already arrived, because the model has no clock or timeout bound. After a crash, the gate refuses every call it had written down but not yet decided. The witness keeps its own list of fingerprints, so the journal can later be compared with a record the operator does not hold.

A separate TLC run confirms that a call can start. It reaches the normal sequence: a call is proposed, written in the journal, its fingerprint sent, stamped by the witness, the stamp received, and the call started. So the checks about starting calls do not hold merely because the model prevents every call from starting.

## What the model checks

Checks of what must never happen (TLA+ names in brackets):

1. **No tool call starts before the witness holds its fingerprint** [`Rule1`, `Rule1Step`]. TLC checks this in two forms. In every state, each call that has started has its fingerprint in the witness's list. In every step, a call that starts in that step had its fingerprint in the list before the step.
2. **The witness's list only grows:** in every step, the new list starts with the whole old list [`Rule2`].
3. **Every fingerprint in the witness's list belongs to a call written in the journal** [`Check3`]. This third rule was added after the first two, to catch a journal that lags behind the witness.
4. **A call starts only if, just before it starts, the gate holds its stamp** [`RunNeedsHeldStamp`].
5. **A call with a refusal in the journal never starts** [`RefusedNeverRuns`].
6. **A fingerprint is sent only for a call already written in the journal** [`JournalBeforeSend`].
7. **In the step where the gate crashes and restarts, every call it had written down but not yet decided gets a refusal in the journal** [`CrashRefusesUndecided`].

One check of what must eventually happen, in the same design with two tool calls (`GateLive.tla`):

8. **Every proposed call is eventually decided**: it starts, is refused, or is lost in a crash [`EveryProposedDecided`]. This assumes weak fairness for each call's gate steps taken together: if at least one of those steps stays possible continuously, the gate eventually takes one of them. Those steps are writing the call in the journal, sending its fingerprint, starting it and refusing it. A refusal counts as a decision, so this check does not show that any call starts.

Given an honest witness with perfect storage, rule 2 holds by construction. The check is there to catch designs where it does not, like the third broken version below.

## What was checked, and the result

TLC checked every order of events the model allows at these sizes: three tool calls, each proposed once; at most one crash of the gate; at most one crash of the witness; and messages that may be lost or arrive late. A message stays available after it arrives, which stands for repeats. In 321,510 distinct states TLC found no broken check. It also reported no deadlock: no state lacked an allowed next step while a call remained undecided. That does not rule out waiting forever while a step remains possible; check 8 covers eventual decisions, under its fairness assumption. One size up, with four tool calls and the same crash limits, the result is the same in 25,995,938 distinct states. In the two-call model, check 8 holds in 5,202 distinct states.

These are results for a model at small sizes. They do not carry over by themselves to larger sizes or to code.

Every check has a broken version of the design that TLC catches, which shows that the check can fail. For each of the eight broken versions, TLC checked each of the eight checks of what must never happen separately: checks 1 to 7, with check 1's two forms counted separately. That makes 64 runs. Each run also checked that values had the expected types (`TypeOK`), with deadlock reporting off. The runs used three tool calls, or two for the version that waits forever. Check 8 was tested separately against that version. Every cell in the table comes from a TLC output:

| Broken version | Checks it breaks | Checks that still hold |
|---|---|---|
| The call starts straight away, skipping the journal, the witness and the stamp | 1 (both forms), 4 | 2, 3, 5, 6, 7 |
| The call starts anyway when the gate gives up waiting | 1 (both forms), 4 | 2, 3, 5, 6, 7 |
| The witness keeps its list only in memory, so a crash wipes it | 1 (both forms), 2 | 3, 4, 5, 6, 7 |
| The fingerprint is sent before the journal entry | 3, 6 | 1 (both forms), 2, 4, 5, 7 |
| The gate starts the call once the witness has stamped it, before the stamp has reached the gate | 4 | 1 (both forms), 2, 3, 5, 6, 7 |
| The gate starts a call it has already refused | 5 | 1 (both forms), 2, 3, 4, 6, 7 |
| The witness records the fingerprint and the tool starts in the same step | 1 (step form), 4 | 1 (state form), 2, 3, 5, 6, 7 |
| The gate's crash refuses nothing, and the gate never gives up (two calls) | 7, and 8 | 1 (both forms), 2, 3, 4, 5, 6 |

In the memory-only witness version, check 1's state form fails when a crash erases the fingerprint of a call that has already started. Its step form fails when a call starts after that erasure.

The full outputs, the commands and the fingerprints of the files checked are in `results/`.

## The code (added 23 Nov 2026)

`code/` holds the design as a Python library, in three parts.

- **The gate** writes each tool call in a journal, sends its fingerprint to the witness (or, in an experimental mode, to two witnesses), and lets the call start only when it holds a stamp that checks out. Each witness is a separate process. It keeps its list as a chain on disk and signs its stamps with an Ed25519 key.
- **An approver for Inspect** sends every tool call of an evaluation through the gate. A call the gate refuses does not run.
- **A checker** reads a run's files afterwards. It answers "pass" only when every check holds and every piece of evidence it needs was there. It answers "fail" when any check fails. Some missing evidence counts as a failure: for example, a missing log for a witness whose stamp a decision relies on. A check that compares timestamps can also fail if the computer's clock jumps backwards. When no check fails but evidence it needs is missing, it answers "pass with incomplete evidence" (`pass_incomplete_evidence`) and lists what was missing, such as the witnesses' public keys from outside the run.

The checker verifies the signatures, each witness's chain and its proofs that the list only grew, the journal against each witness's list, and each recorded effect against the call that was approved. At close, the witnesses also sign the final hash of the gate's decisions, so a refusal rewritten as an approval after the run fails the check. One case stays open. Decisions written before a crash of the gate are signed only at a later close. After a restart, the checker reports the decisions that no witness signed before the restart as incomplete evidence, unless another check fails, and that includes honest crashes. A request to sign carries no authentication, so an operator who can reach a witness while the gate is down could have a rewritten decision file signed before the restart, and that record would pass. Closing this gap needs each decision logged at a witness as it is made, which is not built.

There are 228 unit tests. `code/README.md` describes the interface and every known difference from the model.

## An experiment: two witnesses (added 23 Nov 2026)

This part is an experiment, exploring what to do when the witness is down. One witness is the core design, and it is the one the model checks most thoroughly: with up to four calls, against two calls here.

`model/GateBothWitnesses.tla` extends the design to two witnesses, so that a call can still start while one witness is down, as long as the other witness's stamp reaches the gate. Every fingerprint goes to both. A call may start once the gate holds a stamp from either, and the gate keeps collecting the second stamp afterwards. A witness sends its stamp again when asked about a fingerprint it already holds, and the gate records stamps that arrive after the call has started. An earlier version sent each fingerprint first to the main witness and could ask the backup while the call was waiting. It broke a check, because some started calls ended up in only one witness's list; it is kept for comparison in `model/GateTwoWitnesses.tla`.

With two calls, TLC found no broken check in 4,207,410 distinct states. Twelve broken versions were each tested against each of the ten checks of what must never happen, with check 1's two forms counted separately: 132 runs. Each broke exactly the checks its header comment in `model/wrong/` predicts, and no others. One check of what must eventually happen, that every started call ends up with both stamps, holds with one call. It assumes that a crashed witness eventually restarts, that the gate keeps sending a missing fingerprint again, and that a fingerprint or stamp offered again and again is eventually received and handled. With two calls, TLC ran for nearly nine hours without finishing that check (all outputs are in `results/two_witnesses/`).

**My current view.** The two-witness design is more complex, and more complexity means more places where something can go wrong. A simpler design has a smaller radius for problems, and it is easier for a human reviewer to assess the spec and the code. So I may go back to one witness and rethink what the gate should do when the witness is unresponsive or has to be shut down, and I would welcome comments on that.

## What each gap would let someone do

The record is meant to hold even when the person running the agent, the operator, is not trusted. Each gap below is a way that person, or the agent's own tools, could make the record say something false. One is closed in most runs and one is partly handled; the others are open in this spike.

| Gap | What someone could do with it | Status |
|---|---|---|
| The gate's decision file could be rewritten after the run | Change a refused call to "approved" and add a line saying it ran. That hides a tool that ran against the gate's decision, or turns unfinished tasks into finished ones in an evaluation's results. | Closed for runs without a crash of the gate, when every needed witness signs the decision file's final hash at close: a rewritten file no longer matches. If a witness does not sign, the checker reports incomplete evidence. |
| The window after a crash of the gate | Crash the gate on purpose, rewrite the decisions written before the crash, then restart. The checker reports incomplete evidence, as it does for an honest crash, so the rewrite hides among honest crashes. | Open. Logging each decision at a witness as it is made would close it. |
| A witness signs any request to anchor | Have a witness sign a rewritten decision file while the gate is down, so the rewrite passes. Or have it sign a wrong hash for someone else's honest run, so that run fails. | Open. Requests that only the gate can make would stop strangers; stopping the operator needs each decision logged as it is made. |
| The witnesses run on the same laptop as the gate | Read the witnesses' signing keys from their folders, as anything running under the same user can, the agent's tools included, then sign any stamp or anchor. Every check passes on a record built that way. | Open by design in this spike. A witness has to run on another machine, under someone else's control. |
| The checker relies on the tool's own record of what ran | Run an action outside the gate, or through a tool that records nothing, and it never appears in the record. | Open. Every route out of the agent, the network included, has to pass through the gate. |
| The time checks rely on one machine's clock | Set the clock back after a restart, so an anchor obtained afterwards looks earlier. Clock jumps also raise false alarms in honest runs. | Open. Witnesses with their own clocks, on other machines, would make the times independent. |
| The checker could be given keys from the operator's files | Hand the checker keys the operator holds, and sign everything with them. | Partly handled. When no keys are supplied, the checker reports incomplete evidence. It cannot tell where supplied keys came from, so the reader has to take them from the witnesses, not from the operator. |

## What this does not show

**It checks a design, at small sizes.** Larger sizes are unchecked. The code includes a component for [Inspect](https://inspect.aisi.org.uk), an open-source framework for AI evaluations developed by the UK AI Security Institute and Meridian Labs, that permits or refuses real tool calls using this design. Its comparison with test cases generated from the model's states comes in a later update.

**What the model takes as given:**
- Fingerprints and stamps are labels that cannot be forged, guessed, swapped or made to match another's, and no signing key is ever stolen. The model computes no real hashes over real journal bytes and checks no signatures.
- Storage is perfect. The model's witness list is the witness's saved list, and the journal and that list never lose, corrupt or half-write an entry. Adding a fingerprint to the witness's saved list and sending its stamp happen in one model step, so the code that must make the record durable before releasing a usable stamp is not tested.
- The witness is honest. It shows every reader the same list, never rolls it back, and never stamps what it has not recorded. With one witness and no outside comparison, a dishonest witness could show different readers different lists.
- Every tool call in scope passes through a gate that follows the specified steps. The model contains no malicious gate, and no operator who tampers with the journal or substitutes different tool arguments. Calls to the AI model itself, direct actions by the evaluation's own code, tools run on a model provider's servers, and agents with their own tool loop are outside scope.
- The calls may be at different stages at the same time, in any interleaving. Those orders include every order in which calls are handled one at a time. The model says nothing about the code's thread safety.
- A crash and the restart after it happen in one step, so nothing runs during recovery. A crash during recovery is not modelled, and the recovery code is not tested. Writing "approved" in the journal and starting the tool also happen in one step, so the model never meets a crash between them.
- Messages stay available after they arrive, which stands for repeats, and a repeat that would change nothing is never delivered as a step. Code that handles retries and duplicates is not tested.
- There are no clocks. The gate may give up at any moment, even after the stamp has reached it, so the model says nothing about deadlines or speed. The three- and four-call runs assume no fairness, so they say nothing about whether a call is ever decided; the two-call model checks that.
- The journal is a set of entries: each call when it is written down, and its approval or refusal. It holds no order, no duplicates, no results and no chain linking each entry to the one before. So it records which calls started and says nothing about how they ended. A call lost in a crash before it was written down leaves no record, and the restarted gate does not know it existed.

**What an audit needs:** a reader who checks the records. That means verifying signatures and the chain of entries, checking the witness's proofs that its list only grew, comparing the witness's list with the journal, and comparing each recorded call with the tool's actual arguments. The checker in `code/` does this for runs on one machine, with one limit: it compares each approved call with the function and arguments that the tool's own instrumentation wrote down, so it relies on that instrumentation to report what ran. A record an outside reader can rely on also needs witnesses run by someone other than the operator. In this spike the witnesses, the gate and the evaluation run as the same user on one laptop, so a tool that can read the witnesses' folders could read their signing keys.

**Coming in later updates:**
- the code compared with test cases generated from the model's states;
- that the gate fails safe when the witness returns an error, is slow or is down;
- that retries stay bounded and old stamps cannot be reused;
- that each stamp appears in the witness's list, and that the list only grows;
- the time the gate adds to each call, reported as median, 95th and 99th percentile, stage by stage, with the witness's location stated;
- a medical case study, built at the Apart sprint ([`apart-sprint-custody`](https://github.com/mujeeb-schwarz/apart-sprint-custody)), that attacks the records the way a dishonest operator would.

## How it was made

An AI model (Claude, from Anthropic) wrote the TLA+ from a one-page statement of its meaning, which I approved. A separate Claude session ran TLC. A second AI model (GPT, from OpenAI) then reviewed the model independently, with read-only access, and its findings led to checks 4 to 7 and to stronger broken versions. No person who reads TLA+ has checked the model yet, and I would welcome comments from anyone who does.

The code was made the same way, in eight rounds. In each round one AI model wrote failing tests and then the fixes, and the other reviewed the changes.

## Running it

The runs used TLC2 version 2.19, from `tla2tools.jar` in the [TLA+ tools](https://github.com/tlaplus/tlaplus), on Java 25. From `model/`:

```
java -cp tla2tools.jar tlc2.TLC -config Gate.cfg Gate.tla
java -DTLA-Library=. -cp tla2tools.jar tlc2.TLC -config wrong/WrongRunBeforeJournal.cfg wrong/WrongRunBeforeJournal.tla
```

The other broken versions and `GateLive.tla` use their own `.cfg` files. For `WrongWaitsForever`, add `-deadlock` to turn off deadlock reporting, so that TLC reaches the liveness check:

```
java -DTLA-Library=. -cp tla2tools.jar tlc2.TLC -deadlock -config wrong/WrongWaitsForever.cfg wrong/WrongWaitsForever.tla
```

`results/run_all.py` repeats every run: the main safety and liveness runs, the reachability run, the four-call run and the 64-run table. `results/two_witnesses/matrix_receipts/run_matrix_receipts.py` repeats the 132-run table for two witnesses.

The code's tests use Python 3.11, PyNaCl 1.6 and Inspect (`inspect_ai` 0.3.291). From `code/`:

```
python -m unittest discover -s tests/unit
```

They need no network, API key or real model, and take about a minute.

## Licence

MIT.
