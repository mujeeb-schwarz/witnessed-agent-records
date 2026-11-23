--------------------------- MODULE WrongBothNoRestamp ---------------------------
\* Wrong version of the both-witnesses design: a witness that receives a
\* fingerprint already in its list does not send its stamp again.
\* Expected broken: BothReceiptsHeld only. Once a witness's stamp for a
\* started call is lost, nothing brings it back, so the journal never holds
\* both stamps, even when everything has settled. The lists still fill, so
\* BothListsHoldStarted holds.
\* The wrong step is a setting: WrongBothNoRestamp.cfg replaces RestampOn
\* with NoRestamp below, so that what counts as settled follows this
\* version's own steps.
EXTENDS GateBothWitnesses

\* Re-stamping off.
NoRestamp == FALSE
=============================================================================
