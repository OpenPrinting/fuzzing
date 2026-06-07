# Local Bug Metadata

The public tree does not include concrete vulnerability metadata, private
reproducers, local issue reports, or minimized crash inputs.

For private evaluation, the optional `bugs/<id>/meta.yaml` interface can be
used to track local ground truth. Those files should stay outside public pull
requests unless the issue is already safe to disclose.

Expected metadata fields are:

- `id`
- `title`
- `component`
- `bug_type`
- `target_component`
- `oracle.reached`
- `oracle.triggered`
- `oracle.detected`
- `poc_path`
- `known_poc_allowed_in_seed`
- `timeout_sec`
- `memory_mb`
- `report_path`

`known_poc_allowed_in_seed` should remain `false` for normal evaluation so
seed corpora measure discovery rather than replay.

## Oracle Levels

- `Reached`: execution reaches the target-relevant function, block, or state.
- `Triggered`: the issue precondition is satisfied.
- `Detected`: sanitizer, assertion, custom oracle, crash signal, or other
  detector reports the candidate.

This distinction avoids counting raw crashes as bugs and separates exploration
gains from oracle strength.
