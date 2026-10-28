# Live macOS smoke test

Run `sh app/smoke-live.sh` from the repository root after building the app and CLI. The script launches `ClipVaultApp --serve` with an isolated `CLIPVAULT_SOCKET` and `CLIPVAULT_TEST_MODE=1`, writes a unique synthetic marker with `pbcopy`, waits for its metadata in `clipctl list`, verifies the marker is absent from list output, reads the opaque reference from the matching metadata row and asserts it matches the temporary `CLIPVAULT_TEST_REFERENCE_FILE`, then runs `clipctl copy <ref>` and checks `pbpaste` against the marker. Test mode must use only an in-memory provider, without production Keychain access or persistent vault files. The script stops the server and removes its temporary socket/log artifacts on exit. Do not run concurrently with another ClipVault instance.

The smoke test intentionally does not synthesize Cmd-V because CI sessions may lack Accessibility permission. Manual check: with a disposable item selected, run `clipctl paste clip://<UUID>` in a logged-in macOS GUI session with Accessibility permission granted, then confirm the focused application receives the item via Cmd-V. `copy` and `paste` both resolve to the pasteboard; only `paste` synthesizes Cmd-V.

`sh app/test.sh` runs `swift test --package-path ../vault`, builds the app/CLI package, and runs the Python client/socket contract tests.
