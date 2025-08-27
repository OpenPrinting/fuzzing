# Integrating C‐based OpenPrinting Projects in OSS‐Fuzz Testing

- Year: 2024
- Contributor: Jiongchi Yu


**Contributor**: ttfish

**Organization**: OpenPrinting, The Linux Foundation 

**Mentors**: Till Kamppeter, George-Andrei Iosif, Dongge Liu, Oliver Chang, Ira McDonald, Pratyush Ranjan 

**Useful Links**:
* [Project Page](https://summerofcode.withgoogle.com/programs/2024/projects/QX4kRWZO)
* [Source Code for Fuzz Harnesses](https://github.com/OpenPrinting/fuzzing)
* [OSS-Fuzz](https://github.com/google/oss-fuzz/) Projects
  * [cups](https://github.com/google/oss-fuzz/tree/master/projects/cups)
  * [libcups](https://github.com/google/oss-fuzz/tree/master/projects/libcups)
* [Opportunity Open Source Conference 2024](https://events.canonical.com/event/89/contributions/475/)
* [Ubuntu Summit 2024](https://events.canonical.com/event/51/contributions/540/) - [Ubuntu Summit Repo](https://github.com/iosifache/fuzzingintheopen)

## Project Details

Our goal is to integrate existing OpenPrinting projects into the Google OSS-Fuzz framework to enable continuous fuzz testing, given the lack of fuzz testing in OpenPrinting projects. This integration enhances the detection and resolution of potential issues, thereby improving the robustness of OpenPrinting projects. Based on our integration efforts, we adopt advanced fuzzing techniques to enhance fuzz testing efficiency, including providing structured fuzz inputs, integrating and repairing [Fuzz Introspector](https://github.com/ossf/fuzz-introspector), and employing Large Language Models (LLMs) frameworks such as [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) to assist in generating OSS-Fuzz harnesses.

## Achivement

The overall progress during our integration is as follows:

1. Initialize project [OpenPrinting fuzzing](https://github.com/OpenPrinting/fuzzing), migrate [cups](https://github.com/google/oss-fuzz/tree/master/projects/cups) and [libcups](https://github.com/google/oss-fuzz/tree/master/projects/libcups) into OSS-Fuzz framework.
2. Construct fuzz harnesses for [cups-filters](https://github.com/OpenPrinting/fuzzing/tree/main/projects/cups-filters) and [libcupsfilters](https://github.com/OpenPrinting/fuzzing/tree/main/projects/libcupsfilters), which is pending for merging into OSS-Fuzz.
3. Fix the [fuzz-introspector](https://github.com/ossf/fuzz-introspector) building of cups and libcups for comprehensive fuzz progress analysis. The detailed report is available here: [cups](https://storage.googleapis.com/oss-fuzz-introspector/cups/inspector-report/20241104/fuzz_report.html), [libcups](https://storage.googleapis.com/oss-fuzz-introspector/libcups/inspector-report/20241104/fuzz_report.html).
4. Explores [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) in fuzz harness generation.
5. Help integrate and enable [CI test for libcupsfilters](https://github.com/OpenPrinting/libcupsfilters/pull/58) from previous work.
6. Triage and help fix identified bugs in OpenPrinting projects, illustrated in [here](#fixed-code)
7. Present our work in open source conferences, including [OOSC 2024](https://events.canonical.com/event/89/contributions/475/) and [Ubuntu Summit 2024](https://events.canonical.com/event/51/contributions/540/)

To date, integrated OSS-Fuzz harnesses have identified **41** issues with **21 resolved**, leading to **more than 5000 LoC** changed code. The fuzzing coverage curves are shown below: 

**Fuzzing status for cups**
![image](https://github.com/user-attachments/assets/dca47d22-abff-416a-93e7-52db297a5d92)


**Fuzzing status for libcups**
![image](https://github.com/user-attachments/assets/f30a025a-364e-4b06-addd-28e9760e2de9)

<a name="fixed-code"></a>
## Public Identified Issues and Patches

* [libcups master @a7a28e643cd0f84dcae785f93b72426d644c0619](https://github.com/OpenPrinting/libcups/commit/a7a28e643cd0f84dcae785f93b72426d644c0619)
* [cups master @c67f4add6dfe88fe440a172f49946234694ac211](https://github.com/OpenPrinting/cups/commit/c67f4add6dfe88fe440a172f49946234694ac211)
* [libcups master @882adac2d4999e975a2e6ba797cb27fe10888e99](https://github.com/OpenPrinting/libcups/commit/882adac2d4999e975a2e6ba797cb27fe10888e99)
* [cups master @80fe6815d5941ef8a812087af7869f4c02779f1d](https://github.com/OpenPrinting/cups/commit/80fe6815d5941ef8a812087af7869f4c02779f1d)
* [cups master @7a2d383ee59a90f41d482476edb909165ea9565d](https://github.com/OpenPrinting/cups/commit/7a2d383ee59a90f41d482476edb909165ea9565d)
* [libcups master @83562f7c7e8e4b26da1a8c14f0c5dcdfcb062277](https://github.com/OpenPrinting/libcups/commit/83562f7c7e8e4b26da1a8c14f0c5dcdfcb062277)


## Future Development

1. Based on existing fuzzing projects, integrating more harnesses is more convenient, especially with the help of LLMs.
2. More C/C++-based projects are needed to be integrated, such as [cups-browsed](https://github.com/OpenPrinting/cups-browsed) and [cups-snap](https://github.com/OpenPrinting/cups-snap)
3. Integrating OSS-Fuzz into OpenPrinting projects written in other languages such as Python ([pyppd](https://github.com/OpenPrinting/pyppd)) and Go ([ipp-usb](https://github.com/OpenPrinting/ipp-usb)), is feasible.
4. More effective fuzzing seeds and dictionaries for specific OpenPrinting functionalities are required.
5. End-to-end testing methods can help identify more exploitable bugs in OpenPrinting projects. Manual security audits can also help.\

## TODO

1. Recheck all building with -O0 and -g
2. cups fuzzipp different comparing to libcups fuzzipp
4. Provice Dictionary
6. Fix OSS-Fuzz-Gen
7. libcups delete build.sh in OSS-Fuzz
8. README projects create a table to track building status

## Ackowledgment

I extend my deepest gratitude to everyone who collaborated on this integration project. Specifically, [Till](https://github.com/tillkamppeter) offered crucial domain expertise in OpenPrinting, guiding the priority and direction of our integration efforts. [Andrei](https://github.com/iosifache) shared his knowledge in C/C++ programming and fuzz testing. [Dongge](https://github.com/DonggeLiu) and [Oliver](https://github.com/oliverchang) provided essential coding insights for OSS-Fuzz and OSS-Fuzz-Gen as authors and maintainers. The integration process was smooth, and participating in open-source community events such as OOSC 2024 and the Ubuntu Summit 2024 was enjoyable. I would also like to thank [Arjun](https://github.com/pkillarjun) for initializing some of the fuzz harnesses of cups before our integration and helping migrate the ownership of the fuzzing project under OpenPriting. Many thanks to [Michael R Sweet](https://github.com/michaelrsweet) for helping fix all the reported issues with great patience. None of the progress achieved would have been possible without the invaluable assistance from all of you.