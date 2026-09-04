# Unlicense <img src="https://raw.githubusercontent.com/whiteo/unlicense/main/assets/unlicense.ico" width="40">

[![CI status](https://github.com/whiteo/unlicense/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/whiteo/unlicense/actions/workflows/check.yml) [![Minimum Python version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/) [![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

A Python 3 tool to dynamically unpack executables protected with
Themida/WinLicense 2.x and 3.x.

> **This is a maintained fork** of
> [ergrelet/unlicense](https://github.com/ergrelet/unlicense), which has had no
> commits since August 2023. On top of upstream 0.4.0 it fixes DLL unpacking,
> import resolution, IAT detection for WinLicense 3.x and several crashes and
> hangs — see [CHANGELOG.md](CHANGELOG.md) for the full list. Issues and pull
> requests are welcome here.

Warning: This tool will execute the target executable. Make sure to use this
tool in a VM if you're unsure about what the target executable does.

Note: You need to use a 32-bit Python interpreter to dump 32-bit executables.

## Features

* Handles Themida/Winlicense 2.x and 3.x
* Handles 32-bit and 64-bit PEs (EXEs and DLLs)
* Handles 32-bit and 64-bit .NET assemblies (EXEs only)
* Recovers the original entry point (OEP) automatically
* Recovers the (obfuscated) import table automatically

## Known Limitations

* Doesn't handle .NET assembly DLLs
* Doesn't produce runnable dumps in most cases
* Resolving imports for 32-bit executables packed with Themida 2.x is pretty slow
* Requires a valid license file to unpack WinLicense-protected executables that
  require license files to start

## How To

### Install

There are no tagged releases in this fork yet, but CI builds standalone 32-bit
and 64-bit executables on every push. Open the latest
[PyInstaller Check run](https://github.com/whiteo/unlicense/actions/workflows/pyinstaller.yml)
and download the `unlicense-py3.11-x86` or `unlicense-py3.11-x64` artifact.
Note that GitHub keeps those artifacts for 3 days and only serves them to
signed-in users.

Otherwise, install from source with `pip`:
```
pip install git+https://github.com/whiteo/unlicense.git
```

You can also build the executable yourself by running PyInstaller against
`unlicense.spec`. Remember to build with a 32-bit interpreter if you need to
dump 32-bit targets.

Prebuilt executables of upstream 0.4.0 are available in the
[upstream releases](https://github.com/ergrelet/unlicense/releases), but they
predate every fix listed in the CHANGELOG.

### Use

If you don't want to deal the command-line interface (CLI) you can simply
drag-and-drop the target binary on the appropriate (32-bit or 64-bit)
`unlicense` executable.

Otherwise here's what the CLI looks like:
```
unlicense --help
NAME
    unlicense.exe - Unpack executables protected with Themida/WinLicense 2.x and 3.x

SYNOPSIS
    unlicense.exe PE_TO_DUMP <flags>

DESCRIPTION
    Unpack executables protected with Themida/WinLicense 2.x and 3.x

POSITIONAL ARGUMENTS
    PE_TO_DUMP
        Type: str

FLAGS
    --verbose=VERBOSE
        Type: bool
        Default: False
    --pause_on_oep=PAUSE_ON_OEP
        Type: bool
        Default: False
    --no_imports=NO_IMPORTS
        Type: bool
        Default: False
    --force_oep=FORCE_OEP
        Type: Optional[Optional]
        Default: None
    --target_version=TARGET_VERSION
        Type: Optional[Optional]
        Default: None
    --timeout=TIMEOUT
        Type: int
        Default: 10

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```

## Credits

Original author: [Erwan Grelet](https://github.com/ergrelet). This fork keeps
the upstream GPL-3.0-or-later license.
