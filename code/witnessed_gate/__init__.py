"""witnessed_gate: a gate that lets an AI agent's action start only once a
separate witness process has signed a stamp for the action's journal entry.

The design is specified in ../../model/Gate.tla (one witness),
GateBothWitnesses.tla ("both" mode) and GateTwoWitnesses.tla ("failover"), and
checked there with TLC. Import the parts you need: witnessed_gate.gate (Gate,
WitnessClient, GateCrashed, CloseReport), witnessed_gate.journal,
witnessed_gate.witness (run as its own process), witnessed_gate.faulty_witness
(fault hooks, tests only), witnessed_gate.checker, witnessed_gate.ledger (the
bench ledger interface), witnessed_gate.wire (the effects line,
version 2, and the registry of approved calls).

Package version 0.2.0 implements interface version 2; see ../README.md.
"""
__version__ = "0.2.0"
