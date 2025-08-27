We have deployed OSS-Fuzz on CUPS (2.x), libcups (of CUPS 3.x), libcupsfilters and cups-filters now to efficiently discover crash bugs and vulnerabilities on these components.

But recently, we had a security vulnerability on cups-browsed, which is not covered by OSS-Fuzz. Therefore we want to apply OSS-Fuzz here, too.
