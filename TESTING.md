# Validation

Run the four Cargo checks in README or `./Build-Release.ps1` on Windows. Offline tests use independently constructed examples, temporary directories, loopback TCP/TLS servers and generated test certificates. They require no customer tenant or vendor connection. They cover parsing, feed allowlists and unsupported patterns, group counts, custom configuration, repetitions, cancellation journals, transport verification, HTTP 403 classification, error interpretation, statistics, reports and dashboard rendering.

Live checks are optional: `url-diag test zoom.us --mode https --count 1 --timeout 5s`. Run only on a network where you are authorized to test. A feed download and a connection test are different validations; neither proves every feed entry works. Keep live reports under ignored `results/` and do not commit them.

Before release, run native Windows/Linux/macOS CI, inspect archive allowlists and verify downloaded checksums. Signing and notarization are not configured. This repository does not automatically publish a release on ordinary source pushes.
