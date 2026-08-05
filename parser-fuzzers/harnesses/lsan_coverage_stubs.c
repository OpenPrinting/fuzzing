/* OSS-Fuzz coverage builds do not link LeakSanitizer. */
void __lsan_disable(void) {}
void __lsan_enable(void) {}
