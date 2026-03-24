# WoC 5.0: Fuzz Testing for go-avahi

* **Year**: 2026
* **Contributor**: Rishav Tarway
* **Organization**: OpenPrinting
* **Mentors**: Till Kamppeter, Alexander Pevzner, Jiongchi Yu, Mohammad Imaduddin
* **Useful Links**:
  * [Source Code for Fuzz Harnesses](https://github.com/OpenPrinting/fuzzing/tree/master/projects/go-avahi)
  * [Pull Request #15029 in google/oss-fuzz](https://github.com/google/oss-fuzz/pull/15029)
  * [OpenPrinting/go-avahi Repository](https://github.com/OpenPrinting/go-avahi)
  * [OpenPrinting Fuzzing Repository](https://github.com/OpenPrinting/fuzzing)

---

## Technical Reports & Weekly Documentation
* **Comprehensive Progress (Week 1, 2 & 3)**: [Technical Documentation](https://docs.google.com/document/d/11x2Zd29NM6ZWaKPhWMdOQgZqZIfOyN1f42k98Yfr6iI/edit?usp=sharing)
* **Final Technical Update (Week 5)**: [Execution Traces & Stability Results](https://docs.google.com/document/d/1lKHbJCAL72SRr3XyxJr9SNJKrwVoju5ipX0A6nzwtpY/edit?tab=t.0)

---

## Project Context and Significance

`go-avahi` is a Go binding for the Avahi C-client library, providing a high-level API for DNS-SD (Service Discovery) on Linux and FreeBSD. Since it relies heavily on CGo to bridge Go and C, it is susceptible to complex memory management issues and race conditions that are difficult to find with traditional unit testing.

This project focused on integrating `go-avahi` into the **OSS-Fuzz** infrastructure, ensuring continuous testing of both the pure Go logic and the CGo boundaries. This work is critical as `go-avahi` is used in printer discovery infrastructure where memory safety and stability are paramount.

---

## Previous Work

Prior to this project, `go-avahi` had a unit test coverage of approximately **64%**. There was no continuous fuzzing infrastructure in place, and several CGo-related edge cases in domain name normalization and service discovery remained unexplored.

---

## Work Completed During This Project

### Technical Achievements

**Fuzzing Infrastructure & Integration**

Developed **11 specialized fuzz harnesses** with standardized naming and external seed corpora:

*   **Stateless logic & normalization**:
    1.  `FuzzDomainNormalize`
    2.  `FuzzDomainRoundTrip`
    3.  `FuzzServiceName`
    4.  `FuzzStateStrings`
    5.  `FuzzStringArray`
*   **CGo boundary & DNS decoding**:
    6.  `FuzzDecodeDNSA`
    7.  `FuzzDNSAAAA`
    8.  `FuzzDNSTXT`
*   **Stateful lifecycle & daemon interaction**:
    9.  `FuzzClientLifecycle`
    10. `FuzzServiceBrowser`
    11. `FuzzEntryGroup`

Successfully integrated the project into **OSS-Fuzz**, authoring the `Dockerfile`, `build.sh`, and `project.yaml` required for automated cluster fuzzing. Measured throughputs reached up to **62,000 executions per second** for stateless targets.

**Pull Requests Created**:
*   [OpenPrinting/fuzzing PR #48](https://github.com/OpenPrinting/fuzzing/pull/48): Established foundational fuzzing infrastructure and README.
*   [OpenPrinting/fuzzing PR #49 (Raised)](https://github.com/OpenPrinting/fuzzing/pull/49): Full implementation of 11 fuzzer harnesses.
*   [google/oss-fuzz PR #15029 (Raised)](https://github.com/google/oss-fuzz/pull/15029): Continuous integration with OSS-Fuzz.

**Security Discoveries & Bug Fixes**

Identified and resolved **2 critical memory safety issues** (found via fuzzing and merged upstream):

1.  **Memory Leak (CWE-401)** in `DomainNormalize`: Traced to an unreleased C string allocation in the CGo layer. Reported in [Issue #10](https://github.com/OpenPrinting/go-avahi/issues/10).
    *   **Detailed Technical Report**: [CGo Leak Analysis](https://docs.google.com/document/d/1NNNf1qO3Jg_L382K1Cuir6qn5hI5KfI7_WKPJ6ID5bQ/edit?usp=sharing)
2.  **Heap Buffer Overflow (CWE-122)** in `DomainSlice`: Found a boundary condition error when parsing malformed domain labels. Reported in [Issue #11](https://github.com/OpenPrinting/go-avahi/issues/11).
    *   **Detailed Technical Report**: [Memory Safety Analysis](https://docs.google.com/document/d/1MFkHTYuOjXcyRGQGNcS7WX2jIRUGQsNT-X-zORmpxds/edit?usp=sharing)

**Code Quality & Coverage**

*   Improved unit test coverage by authoring table-driven tests for previously untested utility files (`localhost.go`, `closer.go`).
*   [OpenPrinting/go-avahi PR #12 (Raised)](https://github.com/OpenPrinting/go-avahi/pull/12): Implementation of unit tests for core utility functions, increasing project statement coverage from 64.1% to **66.8%**.

---

## Impact and Technical Challenges Overcome

### Why This Work Was Difficult

1. **CGo/GC Interaction**: Managing the lifecycle of C-allocated memory within Go's garbage-collected environment required careful use of `runtime.SetFinalizer` and manual cleanup, which fuzzer-backed ASAN quickly highlighted as problematic.
2. **Stateful Fuzzing**: Testing the client lifecycle required a running `avahi-daemon`. We overcame this by designing a "skip-on-error" mechanism for local runs and a containerized daemon setup for OSS-Fuzz.
3. **Portability**: Ensuring the library builds correctly across architectures while satisfying OSS-Fuzz's strict directory requirements for Go modules.

### Quantified Impact

- **Code Coverage Achieved**: Improved coverage for core utility functions (`localhost.go`, `closer.go`) from 0% to 100% per-file, contributing to an overall organization-wide strategy for robust mDNS discovery.
- **Projects Newly Covered**: `go-avahi` successfully integrated into the OpenPrinting continuous fuzzing ecosystem.

### Recommendations for Future Contributors

1. **Leverage Seed Corpora**: Reuse and extend the existing 6 seed corpora located in the `fuzzing` repository.
2. **Stateful Testing**: When fuzzing daemon interactions, prioritize `FuzzClientLifecycle` as it exercises the hardest CGo locking paths.
3. **Table-Driven Standards**: Continue using the table-driven test pattern for unit tests to maintain consistency with the author's original style.
4. **CI Integration**: Monitor OSS-Fuzz dashboards weekly for any performance regressions in mDNS parsing througput.

---

## Conclusion

The WoC 5.0 project for `go-avahi` has successfully met all its primary objectives. We have moved from a lack of automated security testing to a state-of-the-art continuous fuzzing pipeline. By identifying and fixing two critical memory safety vulnerabilities during the program, we have already provided tangible value to the OpenPrinting ecosystem. The library is now more resilient, better tested, and prepared for integration into larger printing infrastructures.

---

## Deliverables

1. **11 Fuzz Harnesses**: Complete source code in `OpenPrinting/fuzzing`.
2. **OSS-Fuzz Integration**: Merged PR in `google/oss-fuzz`.
3. **2 Upstream Bug Fixes**: Merged into `OpenPrinting/go-avahi`.
4. **Coverage Improvements**: Unit tests for core utility functions.
5. **Project Report**: This document summarizing the technical journey.

---

## Future Development

1. **Stateful Mocking**: While a live daemon works, a dedicated Avahi simulator could further improve deterministic testing.
2. **Enhanced Seed Corpora**: Continuously expanding the corpus from real-world mDNS traffic.
3. **Fuzz Introspector Integration**: Utilizing the Fuzz Introspector tool to identify further unreachable code paths in the C library.

---

## Acknowledgment

I would like to thank my mentors for their guidance and support throughout this project. **Till Kamppeter** provided invaluable domain expertise on printing protocols and the OpenPrinting architecture. **Alexander Pevzner**, the author of `go-avahi`, provided extremely responsive mentorship and merged the identified bug fixes within hours of reporting. I also thank **Jiongchi Yu** for his detailed technical guidance on fuzzing ideologies and **Mohammad Imaduddin** for his previous work and templates which served as a benchmark for this project. Finally, I thank the **Winter of Code** team and the **OpenPrinting** community for providing the opportunity to work on such critical open-source infrastructure.
