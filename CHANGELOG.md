# Changelog

## [Unreleased]
### Fixed
- Improve reliability of DLL unpacking
- Fix out-of-bounds reads that aborted the import call site scan near the end of a section
- Do not patch import call sites that are too short to hold the replacement instruction
- Discard export hashes claimed by several exports instead of resolving wrappers to an arbitrary one
- Treat wrappers that emulate to a non-export as unresolved
- Bound wrapper emulation and ignore its result when it did not resolve
- Fix the IAT candidate size, start search and page walk for Themida/WinLicense 3.x
- Pass the DLL and its entry point to `rundll32` as a single argument
- Use the SysWOW64 `rundll32` when running a 32-bit interpreter
- Load DLLs with their own directory on the loader search path
- Fix a hang when unprotecting potential OEP ranges one page at a time
- Report the OEP of a DLL through the `DllMain` path on execution faults reported as reads
- Only emit ANSI colors when the console can interpret them
- Fix a temporary file name collision while dumping

### Changed
- Batch import call site patches to cut the number of RPC round-trips
- Gate the frida agent's per-event logging behind `--verbose`

## [0.4.0] - 2023-08-14
### Added
- Add a `--no_imports` option that allows dumping PEs at the original entry point without fixing imports

### Fixed
- Fix a potential deadlock when dumping DLLs
- Improve version detection for Themida/Winlicense 2.x
- Improve version detection for Themida/Winlicense 3.x
- Improve .text section detection for Themida/Winlicense 3.x
- Fix `lief.not_found` exception happening when dumping certain MinGW EXEs
- Fix TLS callback detection for some 32-bit EXEs
- Handle wrapped imports from Themida/Winlicense 3.1.4.0
- Improve IAT search algorithm for Themida/Winlicense 3.x
- Allow unpacking EXEs that require admin privilege at medium integrity level
- Properly skip DllMain invocations on thread creation/deletion when dumping DLLs

### Changed
- Silence some misleading "error" logs that were emitted

## [0.3.0] - 2022-07-22
### Fixed
- Fix a couple of bugs with the IAT search and resolution for Themida/Winlicense 3.x
- Fix potentially invalid IAT truncations for Themida/WinLicense 3.x
- OEP detection now works in a runtime-agnostic manner (and handles virtualized entry points and Delphi executables)
- TLS callbacks are now properly detected and skipped

## [0.2.0] - 2022-05-31
### Added
- Handle unpacking of 32-bit and 64-bit DLLs
- Handle unpacking of 32-bit and 64-bit .NET assembly PEs (EXE only)
- OEP detection times out after 10 seconds by default. The duration can be
  changed through the CLI.

### Fixed
- Improve .text section detection for Themida/Winlicense 2.x

## [0.1.1] - 2022-04-06
### Fixed
- Fix IAT patching in some cases for Themida/Winlicense 3.x
- Fix inability to read remote chunks of memory bigger than 128 MiB
- Improve version detection to handle packed Delphi executables
- Improve IAT search algorithm for Themida/Winlicense 3.x
- Gracefully handle bitness mismatch between interpreter and target PEs
- Fix IAT truncation issue for IATs bigger than 4 KiB

## [0.1.0] - 2021-11-13

Initial release with support for Themida/Winlicense 2.x and 3.x.  
This release has been tested on Themida 2.4 and 3.0.
