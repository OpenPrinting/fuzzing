# fuzzing
This repository is used for fuzzing OpenPrinting projects. It contains fuzz harnesses, corpus and documentation for [OSS-Fuzz](https://github.com/google/oss-fuzz) workflow. 

## OpenPrinting projects

OpenPrinting is the premier open-source printing system for Unix-like operating systems, managed by the Linux Foundation. The majority of OpenPrinting's projects are developed in C. Fuzzing has been demonstrated to effectively detect vulnerabilities in C-based programs. Therefore, it is crucial to adopt fuzzing within OpenPrinting projects to enhance the security and reliability of these systems.

Existing integrated OpenPrinting projects include:

+ [CUPS](https://github.com/OpenPrinting/cups)
+ [libcups](https://github.com/OpenPrinting/libcups)