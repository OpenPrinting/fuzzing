# Seed corpus

The archives in this directory are startup corpora for the matching OSS-Fuzz
binaries. Archive names follow OSS-Fuzz's
`<fuzzer>_seed_corpus.zip` convention.

The inputs are synthetic test material created for this fuzzing project. Safe
seeds from earlier development iterations were deduplicated into the current
archives; crash artifacts, private print jobs, and user documents are not
included. The corpus covers bounded PDF, PCLm, PostScript, raster, image, PPD,
command, and text structures. OSS-Fuzz will evolve and minimize these startup
inputs after deployment.

To the extent that copyright applies to these generated inputs, they are
licensed under the repository's Apache-2.0 license.
