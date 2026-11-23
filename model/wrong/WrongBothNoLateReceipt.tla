------------------------- MODULE WrongBothNoLateReceipt -------------------------
\* Wrong version of the both-witnesses design: a stamp that reaches the
\* gate after the call has run is not recorded.
\* Expected broken: BothReceiptsHeld only, in orders where the second
\* witness's stamp arrives after the run. The lists still fill, so
\* BothListsHoldStarted holds.
\* The wrong step is a setting: WrongBothNoLateReceipt.cfg replaces
\* LateReceiptsOn with NoLateReceipt below, so that what counts as settled
\* follows this version's own steps.
EXTENDS GateBothWitnesses

\* Receipts after the run off.
NoLateReceipt == FALSE
=============================================================================
