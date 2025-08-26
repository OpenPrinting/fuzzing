# fuzzing
This repository is used for fuzzing OpenPrinting projects. It contains fuzz harnesses, corpus and documentation for [OSS-Fuzz](https://github.com/google/oss-fuzz) workflow. 

## OpenPrinting Projects

OpenPrinting develops IPP-based printing technology for Linux®/Unix® operating system. The majority of OpenPrinting's projects are developed in C. Fuzzing has been demonstrated to effectively detect vulnerabilities in C-based programs. Therefore, it is crucial to adopt fuzzing within OpenPrinting projects to enhance the security and reliability of these systems.

Existing integrated OpenPrinting projects include:

+ [CUPS](https://github.com/OpenPrinting/cups)
+ [libcups](https://github.com/OpenPrinting/libcups)
+ [cups-filters](https://github.com/OpenPrinting/cups-filters)
+ [libcupsfilters](https://github.com/OpenPrinting/libcupsfilters)

## Debugging Guidance

+ [Build](docs/build.md)
+ [Bug Triage](docs/triage.md)

## Bug Reporting
For any security-related findings using this repo, **DO NOT** post the details directly in the public issue tracker of OpenPrining projects. Please consider reporting security vulnerabilities with the following options:

1. Github Security Advisory Panel: Directly report security vulnerabilities to the project's advisory panel and cc the developers of this repo if possible. You can find the detailed guidance for reporting the advisroy in each OpenPrinting project. 

2. Email the Developer Team: Reporting security issues by emailing the developer team listed in each OpenPrinting project or simply contact the developers of this repo.


![](https://avatars.githubusercontent.com/u/20563597?s=200&v=4 "OpenPrinting logo")

Fuzz Testing in [OpenPrinting](https://openprinting.github.io/)
---

OpenPrinting is a free software organization under the Linux Foundation that develops and promotes printing standards for Linux and other Unix-like operating systems. Most of the projects in OpenPrinting are developed in C/C++, which is prone to memory violation vulnerabilities. Existing OpenPrinting projects lack comprehensive dynamic testing techniques during the development. Therefore, integrating advanced fuzzing techniques is a promising approach for enhancing the security of OpenPrinting.

## Projects
- cups
- libcups
- cups-filters
- libcupsfilters

## GSoC
- [GSoC 2024 - Integrating C-based OpenPrinting Projects in OSS-Fuzz Testing](https://github.com/OpenPrinting/fuzzing/wiki/Integrating-C%E2%80%90based-OpenPrinting-Projects-in-OSS%E2%80%90Fuzz-Testing-(GSoC-2024))