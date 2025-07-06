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
com.apple.kernel:__text:FFFFFE0008859D2C
com.apple.kernel:__text:FFFFFE0008859D2C ; =============== S U B R O U T I N E =======================================
com.apple.kernel:__text:FFFFFE0008859D2C
com.apple.kernel:__text:FFFFFE0008859D2C ; Attributes: bp-based frame
com.apple.kernel:__text:FFFFFE0008859D2C
com.apple.kernel:__text:FFFFFE0008859D2C ; __int64 __fastcall sub_FFFFFE0008859D2C(__int64, __int64, __int64, __int64, __int64, __int64, __int64)
com.apple.kernel:__text:FFFFFE0008859D2C sub_FFFFFE0008859D2C                    ; CODE XREF: sub_FFFFFE00087F3AE8+894↑p
com.apple.kernel:__text:FFFFFE0008859D2C                                         ; sub_FFFFFE00087F3AE8+90C↑p ...
com.apple.kernel:__text:FFFFFE0008859D2C
com.apple.kernel:__text:FFFFFE0008859D2C var_50          = -0x50
com.apple.kernel:__text:FFFFFE0008859D2C var_48          = -0x48
com.apple.kernel:__text:FFFFFE0008859D2C var_40          = -0x40
com.apple.kernel:__text:FFFFFE0008859D2C var_38          = -0x38
com.apple.kernel:__text:FFFFFE0008859D2C var_30          = -0x30
com.apple.kernel:__text:FFFFFE0008859D2C var_28          = -0x28
com.apple.kernel:__text:FFFFFE0008859D2C var_20          = -0x20
com.apple.kernel:__text:FFFFFE0008859D2C var_18          = -0x18
com.apple.kernel:__text:FFFFFE0008859D2C var_10          = -0x10
com.apple.kernel:__text:FFFFFE0008859D2C var_8           = -8
com.apple.kernel:__text:FFFFFE0008859D2C var_s0          =  0
com.apple.kernel:__text:FFFFFE0008859D2C var_s8          =  8
com.apple.kernel:__text:FFFFFE0008859D2C
com.apple.kernel:__text:FFFFFE0008859D2C                 BTI             c
com.apple.kernel:__text:FFFFFE0008859D30                 CBZ             X0, loc_FFFFFE0008859DDC
com.apple.kernel:__text:FFFFFE0008859D34                 PACIBSP
com.apple.kernel:__text:FFFFFE0008859D38                 STP             X28, X27, [SP,#-0x10+var_50]!
com.apple.kernel:__text:FFFFFE0008859D3C                 STP             X26, X25, [SP,#0x50+var_40]
com.apple.kernel:__text:FFFFFE0008859D40                 STP             X24, X23, [SP,#0x50+var_30]
com.apple.kernel:__text:FFFFFE0008859D44                 STP             X22, X21, [SP,#0x50+var_20]
com.apple.kernel:__text:FFFFFE0008859D48                 STP             X20, X19, [SP,#0x50+var_10]
com.apple.kernel:__text:FFFFFE0008859D4C                 STP             X29, X30, [SP,#0x50+var_s0]
com.apple.kernel:__text:FFFFFE0008859D50                 ADD             X29, SP, #0x50
com.apple.kernel:__text:FFFFFE0008859D54                 MOV             X20, X6
com.apple.kernel:__text:FFFFFE0008859D58                 MOV             X25, X5
com.apple.kernel:__text:FFFFFE0008859D5C                 MOV             X26, X4
com.apple.kernel:__text:FFFFFE0008859D60                 MOV             X21, X3
com.apple.kernel:__text:FFFFFE0008859D64                 MOV             X23, X2
com.apple.kernel:__text:FFFFFE0008859D68                 MOV             X22, X1
com.apple.kernel:__text:FFFFFE0008859D6C                 MOV             X19, X0
com.apple.kernel:__text:FFFFFE0008859D70                 TBNZ            W6, #9, loc_FFFFFE0008859D7C ; <-- This is the instruction we will patch
```

The offsets in patch_tss_crash.c are for my macOS build, 26.0 Beta (25A5295e), and if you have any other version, you must modify these offsets to prevent possible damage to your system.

### Building and Running

You can build this project using `make` and run the outputted binary at `build/patch_tss_crash`.

### Older versions

For specific older versions of macOS which I have found the offsets for, their C files are in the `old` directory. You can replace the contents of `patch_tss_crash.c` with the contents of the file for your version, and then build as normal.
