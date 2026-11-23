------------------------ MODULE WrongBothCatchUpOneWay ------------------------
\* Wrong version of the both-witnesses design: catch-up runs one way only,
\* to the main witness. A fingerprint whose copy to the backup was lost is
\* never sent to the backup again.
\* Expected broken: BothListsHoldStarted and BothReceiptsHeld. A call can
\* start on the main witness's stamp while the backup's copy is lost, and
\* once everything has settled the backup's list still lacks it, and the
\* journal has no stamp from the backup for it. Rule 1 holds, since the
\* main witness holds the fingerprint.
\* The wrong step is a setting: WrongBothCatchUpOneWay.cfg replaces
\* CatchUpTo, the witnesses catch-up sends to, with OneWay below.
EXTENDS GateBothWitnesses

\* Catch-up sends only to the main witness.
OneWay == {"main"}
=============================================================================
