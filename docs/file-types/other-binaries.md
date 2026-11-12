# Linux, macOS and Android

**ELF** and **Mach-O** binaries get the same static triage as Windows executables — header,
sections and entropy, imports and libraries, packers (UPX) — plus the **Code** tab (functions,
pseudocode, call graph) and the [Go](go.md) tab when they are Go.

![Binary tab of an ELF backdoor](../assets/shots/other-binaries/elf.webp){ .shot }

![Code tab of the same ELF](../assets/shots/other-binaries/elf-code.webp){ .shot }

**APK** packages are extracted: their files and native libraries (one ELF
per ABI) are analysed as nested children, and the [Machine Learning](../engines/ml.md) tab
scores them with the EMBER2024 APK model.
