# Ghidra headless decompiler integration

- Upstream: National Security Agency, [Ghidra](https://github.com/NationalSecurityAgency/ghidra).
- API/runtime reference: `Ghidra_12.0.4_build`, application version 12.0.4, Java minimum 21.
- Upstream license: Apache License 2.0. The complete original text is in `LICENSE.txt`.
- Original upstream notice: preserved verbatim in `UPSTREAM-NOTICE.txt`.

KSword invokes a separately installed Ghidra runtime through its public headless
and Java decompiler APIs. This directory does not contain the Ghidra engine,
third-party runtime libraries, a JDK, or any copied decompiler implementation.
The `GhidraPseudocode` adapter script embedded in
`UI/Decompiler/GhidraDecompiler.cpp` is original KSword code and is governed by
the repository license. It calls `DecompInterface`, `PrettyPrinter`, and the
Ghidra script API; it does not relicense those APIs or the Ghidra runtime.

The Apache 2.0 separation and attribution obligations are compatible with
KSword's current Community Source License 1.6 sections 9.3–9.5 and 16.4. The
integration does not link, copy, or embed a GPL decompiler. The independently
installed Ghidra runtime retains its own licenses and patent grants; KSword's
license does not limit rights in those components.

If a distributor later bundles a Ghidra runtime, they must preserve that
specific runtime's complete `LICENSE`, `NOTICE`, `licenses/`, component notices
and any component-specific redistribution obligations. This notice and the
top-level Apache license alone are not a license inventory for the complete
Ghidra distribution. A JDK also has independent terms and must be handled
separately; this integration does not bundle or relicense one.

Primary references:

- [Pinned Ghidra LICENSE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0.4_build/LICENSE)
- [Pinned Ghidra NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0.4_build/NOTICE)
- [Pinned Java requirements](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.0.4_build/Ghidra/application.properties)
- [Official DecompInterface API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html)

