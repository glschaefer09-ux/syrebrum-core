# Contributing

Thanks for helping. Contributions are accepted under Apache-2.0.

For questions, or to talk through a larger change before you start, use
[GitHub Discussions](https://github.com/glschaefer09-ux/syrebrum-core/discussions). Report bugs as issues and
security problems as described in [SECURITY.md](SECURITY.md).

1. Sign off each commit (`git commit -s`) to certify the
   [Developer Certificate of Origin](https://developercertificate.org/):
   you wrote it or have the right to submit it under Apache-2.0.
2. No new runtime dependencies without first raising it in Discussions: being standard-library
   only is a core promise.
3. Add a test for every behaviour you change, especially every deny path.
4. Run `scripts/check.sh` before opening a pull request.
5. Never include secrets, customer data or internal host names.

New source files need the two-line SPDX header used in existing files.
