# Changelog

## 1.1 (2026-09-15)

Bug fixes and documentation corrections following a code review. No API changes.

- Input buffers passed to `CryptProtectData` / `CryptUnprotectData` are now allocated outside the
  GC and explicitly zeroed and freed, removing a latent use-after-free (#1).
- `exn:fail:dpapi` is now raised only when a Windows DPAPI call reports failure, so its
  `error-code` is always a real Windows error code. Local validation failures, including access to a
  destroyed protected value, raise a plain `exn:fail` (#2).
- `import-protected-bytes` now yields `#f` for the description when none was stored, as documented,
  instead of `""` (#3).
- Nested use of `with-decrypted-data`, `export-protected-bytes`, or `destroy-protected-value!` on
  the same protected value from within its own callback now raises an error instead of deadlocking.
  Waiting for access is break-enabled. The behaviour under `kill-thread` is documented (#4).
- Error code `0x8009000D` is now correctly labelled `NTE_NO_KEY`; `0x80090009` (`NTE_BAD_FLAGS`)
  was added (#5).
- Documentation: the `#:description` default of `export-protected-bytes` is shown correctly;
  `make-protected-value` is documented as encrypting a copy of its input, with guidance on zeroing
  the original; installation instructions now use the package catalog.
- Tests run on Windows in GitHub Actions. DPAPI-dependent tests print a notice when skipped on
  other platforms.

## 1.0 (2026-09-14)

Initial release.
