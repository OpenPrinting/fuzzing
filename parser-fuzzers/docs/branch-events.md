# Branch Event and Solver Result Format

The SMT patcher consumes one local branch event at a time. The event describes
which input field should be patched so the branch condition becomes true.

## Branch Event JSON

Required fields:

- `target_id`: target or harness identifier.
- `input_path`: path to the concrete input used for tracing.
- `input_sha256`: SHA-256 of the concrete input.
- `offset`: byte offset of the symbolic field.
- `width`: field width in bytes; first version supports `1`, `2`, `4`, `8`.
- `endianness`: `little` or `big`.
- `signed`: boolean annotation for the source comparison.
- `op`: one of `eq`, `ne`, `ult`, `ule`, `ugt`, `uge`, `slt`, `sle`, `sgt`, `sge`.
- `rhs`: integer right-hand side, decimal or hex.
- `description`: human-readable branch description.

Example:

```json
{
  "target_id": "synthetic_eq_u8",
  "input_path": "work/smoke/input.bin",
  "input_sha256": "64 hex characters",
  "offset": 0,
  "width": 1,
  "endianness": "little",
  "signed": false,
  "op": "eq",
  "rhs": 65,
  "description": "first byte must become ASCII A"
}
```

## Solver Result JSON

Required fields:

- `status`: `sat`, `unsat`, or `already_satisfied`.
- `solver_ms`: wall-clock solver time in milliseconds.
- `patches`: list of byte patches.
- `reason`: backend or failure summary.
- `event`: original branch event.

Each patch contains:

- `offset`
- `old_hex`
- `new_hex`
- `width`

The patcher verifies `input_sha256` and `old_hex` before writing a generated
candidate into `work/corpus/smt`.
