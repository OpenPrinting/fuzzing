# GSoC 2026 - Advanced System-Level Fuzzing for OpenPrinting

Proposal topic:

```text
Advanced System-Level Fuzzing for OpenPrinting: Deep State Exploration and LLM-Augmented Mutation
```

This contribution contains a proposal snapshot plus a runnable fuzzing project
for OpenPrinting parser and filter exploration.

## Layout

```text
this contribution/
|-- Announcement.md
|-- Proposal.md
|-- README.md
`-- smt-fuzzer/
    |-- README.md
    |-- src/
    |-- configs/
    |-- scripts/
    `-- docs/
```

## What To Run

Start here:

```bash
cd smt-fuzzer
scripts/setup_tui.sh
```

Recommended quick target test when system CUPS filters are available:

```bash
scripts/run_local_cups_filters_campaign.sh /usr/lib/cups/filter 1 2 5 configs/parser_targets.yaml
```

Then choose a target path:

```text
clone-only smoke
      |
      +--> recommended quick target test
      |
      `--> isolated ASan cups-filters campaign
```

The detailed commands live in `smt-fuzzer/README.md`.

## Security Note

This public snapshot keeps unpublished issue details out of the contribution
tree. Generated campaign output stays under `smt-fuzzer/work/` and is ignored
by git.
