# `fuzzing`

This repository hosts all fuzzing efforts for OpenPrinting projects, including fuzzing harnesses, corpus files, and integrations with [OSS-Fuzz](https://github.com/google/oss-fuzz).

## Existing OSS-Fuzz Integrations

See the `/projects` folder for details on existing integrations of OpenPrinting projects with OSS-Fuzz.

## cups-filters Parser and Filter Fuzzers

The `/parser-fuzzers` directory contains the maintained libFuzzer harnesses for
the current cups-filters split stack. It provides 25 continuous OSS-Fuzz targets,
the existing `fuzz_pdf` compatibility target, structured mutators, semantic
output oracles, seed corpora, and dictionaries.

Start with:

```bash
make -C parser-fuzzers check
```

The [GSoC 2026 final report](contributions/GSoC%202026%20-%20Advanced%20System-Level%20Fuzzing%20for%20OpenPrinting/Final%20report.md)
summarizes the project goals, design, deliverables, validation, and upstream
integration status.

## Contributing

The fuzzing efforts in OpenPrinting were initiated and driven by talented Google Summer of Code and Winter of Code contributors. Check the `/contributions` folder for details about ongoing projects and past success stories.

For contributions, please check the `/docs` folder for documentation on creating new integrations and adding harnesses. Additionally, consider checking the talks and workshops we hosted in the past in the `/talks` folder.

## Bug Reporting

> [!CAUTION]
> If you discover potential security issues in OpenPrinting projects (with or without using this repository), **DO NOT** post details directly in OpenPrinting's public issue trackers.

Please use one of the following methods to report security issues in OpenPrinting projects:

1. **Use GitHub Security Advisory Panel**: Report security vulnerabilities directly to the project's advisory panel and CC the developers of this repository when possible. Detailed guidance for reporting security issues can be found in each OpenPrinting project's documentation.

2. **Email the development team**: Report security issues by emailing the development team listed in each OpenPrinting project. Alternatively, contact the contributors of this repository directly.
