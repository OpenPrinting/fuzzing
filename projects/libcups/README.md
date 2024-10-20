# Fuzzing Harness for libcups

The code in this directory contain:

1. Fuzzing harness for OSS-Fuzz
2. Fuzzing seeds related to unit tests

## Local Building and Triage

```bash
apt-get update && apt-get install -y make autoconf automake libtool build-essential libavahi-client-dev libgnutls28-dev libnss-mdns zlib1g-dev libsystemd-dev libssl-dev # libssl-dev is extra required
apt-get install -y git vim gdb clang # for debugging

# build with O0
sed -i 's/-O[0-9s]/-O0/g' configure
```