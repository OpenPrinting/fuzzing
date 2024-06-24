# fuzzing
This repository is used for fuzzing OpenPrinting projects. It contains fuzz harnesses, corpus and documentation for [OSS-Fuzz](https://github.com/google/oss-fuzz) workflow. 

## OpenPrinting Projects

OpenPrinting develops IPP-based printing technology for Linux®/Unix® operating system. The majority of OpenPrinting's projects are developed in C. Fuzzing has been demonstrated to effectively detect vulnerabilities in C-based programs. Therefore, it is crucial to adopt fuzzing within OpenPrinting projects to enhance the security and reliability of these systems.

Existing integrated OpenPrinting projects include:

+ [CUPS](https://github.com/OpenPrinting/cups)
+ [libcups](https://github.com/OpenPrinting/libcups)

## Bug Reporting
For any security-related findings using this repo, **DO NOT** post the details directly in the public issue tracker of OpenPrining projects. Please consider reporting security vulnerabilities with the following options:

1. Github Security Advisory Panel: Directly report security vulnerabilities to the project's advisory panel and cc the developers of this repo if possible. You can find the detailed guidance for reporting the advisroy in each OpenPrinting project. 

2. Email the Developer Team: Reporting security issues by emailing the developer team listed in each OpenPrinting project or simply contact the developers of this repo.