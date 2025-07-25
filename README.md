# patch_tss_crash

Modify the macOS kernel using KextRW to disable the crash that occurs when calling thread_set_state

## Background

Since around macOS 14.5, the XNU kernel has been modified to disallow the usage of the tss_should_crash boot-arg to disable the crash that occurs when calling thread_set_state. This is a problem for many debugging tools which rely on this functionality, like Frida.

## Usage

First, install the KextRW kernel extension from https://github.com/BlueFalconHD/KextRW and run the tests. After you confirm those are working, use `make install_lib` there to install libkextrw to the system.

Additionally, you must install the Capstone disassembly framework. You can do this using `brew install capstone`.

### Finding the correct offset

Open a static analysis tool like IDA Pro, Ghidra, or any other using the path listed in the first few lines of `kmutil inspect`'s output. Search for the string `com.apple.private.thread-set-state`. You should find one with 2-3 references from a single subroutine. That is the `thread_set_state_internal` subroutine, though the name is probably stripped. From there, modify the #defines in `patch_tss_crash.c` to match the offset of said subroutine. Also calculate the offset of the TBNZ check that will be patched by subtracting the start address of the subroutine from the address of the TBNZ instruction. You can see an example of the instruction below:

```
com.apple.kernel:__text:FFFFFE000886DFEC sub_FFFFFE000886DFEC                    ; CODE XREF: sub_FFFFFE0008807B5C+894↑p
com.apple.kernel:__text:FFFFFE000886DFEC                                         ; sub_FFFFFE0008807B5C+90C↑p ...
com.apple.kernel:__text:FFFFFE000886DFEC
com.apple.kernel:__text:FFFFFE000886DFEC                 BTI             c
com.apple.kernel:__text:FFFFFE000886DFF0                 CBZ             X0, loc_FFFFFE000886E09C
com.apple.kernel:__text:FFFFFE000886DFF4                 PACIBSP
com.apple.kernel:__text:FFFFFE000886DFF8                 STP             X28, X27, [SP,#-0x10+var_50]!
com.apple.kernel:__text:FFFFFE000886DFFC                 STP             X26, X25, [SP,#0x50+var_40]
com.apple.kernel:__text:FFFFFE000886E000                 STP             X24, X23, [SP,#0x50+var_30]
com.apple.kernel:__text:FFFFFE000886E004                 STP             X22, X21, [SP,#0x50+var_20]
com.apple.kernel:__text:FFFFFE000886E008                 STP             X20, X19, [SP,#0x50+var_10]
com.apple.kernel:__text:FFFFFE000886E00C                 STP             X29, X30, [SP,#0x50+var_s0]
com.apple.kernel:__text:FFFFFE000886E010                 ADD             X29, SP, #0x50
com.apple.kernel:__text:FFFFFE000886E014                 MOV             X20, X6
com.apple.kernel:__text:FFFFFE000886E018                 MOV             X25, X5
com.apple.kernel:__text:FFFFFE000886E01C                 MOV             X26, X4
com.apple.kernel:__text:FFFFFE000886E020                 MOV             X21, X3
com.apple.kernel:__text:FFFFFE000886E024                 MOV             X23, X2
com.apple.kernel:__text:FFFFFE000886E028                 MOV             X22, X1
com.apple.kernel:__text:FFFFFE000886E02C                 MOV             X19, X0
com.apple.kernel:__text:FFFFFE000886E030                 TBNZ            W6, #9, loc_FFFFFE000886E03C ; <-- Patch to no-op
com.apple.kernel:__text:FFFFFE000886E034                 LDRSH           W8, [X19,#0xC0]
com.apple.kernel:__text:FFFFFE000886E038                 TBZ             W8, #0x1F, loc_FFFFFE000886E188 ; <-- Patch to unconditional branch
```

The offsets in patch_tss_crash.c are for my macOS build, 26.0 Beta (25A5295e), and if you have any other version, you must modify these offsets to prevent possible damage to your system.

### Building and Running

You can build this project using `make` and run the outputted binary at `build/patch_tss_crash`.

### Older versions

For specific older versions of macOS which I have found the offsets for, their C files are in the `old` directory. You can replace the contents of `patch_tss_crash.c` with the contents of the file for your version, and then build as normal.
