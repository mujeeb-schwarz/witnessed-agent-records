---------------------- MODULE WrongBothAcceptsUnaskedStamp ----------------------
\* Wrong version of the both-witnesses design: the gate accepts a stamp from
\* a witness it never asked.
\* In the design the gate asks both witnesses for every fingerprint, so an
\* unasked stamp needs a send that skips one. This file therefore adds three
\* steps to the spec in GateBothWitnesses.tla: a send to the main witness
\* only, the backup copying fingerprints from the main witness's list on its
\* own and stamping them, and the gate taking a stamp without checking that
\* it asked that witness.
\* Expected broken: StampsOnlyFromAsked only. Stamps can't be forged, so a
\* stamp from the backup still means the backup holds the fingerprint, and
\* rule 1 holds. Only the gate's record of whom it asked is wrong.
\* BothReceiptsHeld holds too: the call runs on a stamp the gate has
\* recorded, and catch-up brings the other witness's.
EXTENDS GateBothWitnesses

\* The circumstance, part 1: a send that skips the backup.
SendToMainOnly(a) ==
    /\ status[a] = "journaled"
    /\ Entry(a, "intent") \in journal
    /\ fpInFlight' = [fpInFlight EXCEPT !["main"] = @ \cup {Fp(a)}]
    /\ asked' = [asked EXCEPT !["main"] = @ \cup {Fp(a)}]
    /\ status' = [status EXCEPT ![a] = "waiting"]
    /\ UNCHANGED <<journal, effects, stampsInFlight, stampVars, witnessVars,
                   gateCrashes>>

\* The circumstance, part 2: the backup copies a fingerprint from the main
\* witness's list into its own, and stamps it, unasked.
BackupCopiesMain(f) ==
    /\ witnessUp["backup"]
    /\ f \in Range(witnessList["main"])
    /\ f \notin Range(witnessList["backup"])
    /\ witnessList' = [witnessList EXCEPT !["backup"] = Append(@, f)]
    /\ stampsInFlight' = [stampsInFlight EXCEPT !["backup"] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, fpInFlight, stampVars,
                   witnessUp, witnessCrashes, gateCrashes, asked>>

\* The wrong step: the gate takes a stamp from any witness, without checking
\* that it sent that witness the fingerprint.
AcceptAnyStamp(w, f) ==
    /\ f \in stampsInFlight[w]
    /\ status[ActionOf(f)] = "waiting"
    /\ f \notin stampsHeld[w]
    /\ stampsHeld' = [stampsHeld EXCEPT ![w] = @ \cup {f}]
    /\ receipts' = [receipts EXCEPT ![w] = @ \cup {f}]
    /\ UNCHANGED <<status, journal, effects, messageVars, witnessVars,
                   gateCrashes, asked>>

WrongNext ==
    \/ Next
    \/ \E a \in Actions : SendToMainOnly(a)
    \/ \E f \in Fingerprints : BackupCopiesMain(f)
    \/ \E w \in Witnesses, f \in Fingerprints : AcceptAnyStamp(w, f)
WrongSpec == Init /\ [][WrongNext]_vars
=============================================================================
