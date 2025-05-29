# arte-Executable-Header-Fuzzer
Fuzzes the executable header of a given file to test for parsing vulnerabilities in emulators. Uses a combination of bit-flipping, random value injection, and header field manipulation based on known PE/ELF/Mach-O header structures. Reports any crashes or unexpected behavior observed during emulation (using a simple subprocess call to an emulator like QEMU). - Focused on Tools designed to dynamically emulate and analyze potentially malicious artifacts like shellcode, PE files, or other encoded payloads in a sandboxed environment for behavior analysis and threat assessment.

## Install
`git clone https://github.com/ShadowStrikeHQ/arte-executable-header-fuzzer`

## Usage
`./arte-executable-header-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-e`: Path to the emulator executable. Defaults to qemu-system-x86_64.
- `-o`: Directory to store the fuzzed files. Defaults to fuzzed_files.
- `-i`: Number of fuzzing iterations. Defaults to 10.
- `-f`: No description provided
- `--seed`: Seed for the random number generator. If not provided, a random seed is used.

## License
Copyright (c) ShadowStrikeHQ
