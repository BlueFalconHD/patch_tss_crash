# patch_tss_crash

Modify the macOS kernel using KextRW to disable the crash that occurs when calling thread_set_state

## Background

Since around macOS 14.5, the XNU kernel has been modified to disallow the usage of the tss_should_crash boot-arg to disable the crash that occurs when calling thread_set_state. This is a problem for many debugging tools which rely on this functionality, like Frida.

## Usage

First, install the KextRW kernel extension from https://github.com/BlueFalconHD/KextRW and run the tests. After you confirm those are working, use `make install_lib` there to install libkextrw to the system.

Additionally, you must install the Capstone disassembly framework. You can do this using `brew install capstone`.

### Finding the correct offset

Open a static analysis tool like IDA Pro, Ghidra, or any other using the path listed in the first few lines of `kmutil inspect`'s output. Search for the string `com.apple.private.thread-set-state`. You should find one with 2-3 references from a single subroutine. That is the `thread_set_state_internal` subroutine, though the name is probably stripped. From there, modify the #defines in `patch_tss_crash.c` to match the offset of said subroutine. Also calculate the offset of the TBZ check that will be patched by subtracting the start address of the subroutine from the address of the TBZ instruction. You can see an example of the instruction below:

```
com.apple.kernel:__text:FFFFFE00087C1548 ; __int64 __fastcall sub_FFFFFE00087C1548(__int64, __int64, void *, __int64, __int64, __int64, __int64)
com.apple.kernel:__text:FFFFFE00087C1548 sub_FFFFFE00087C1548                    ; CODE XREF: sub_FFFFFE000875FCC8+888↑p
com.apple.kernel:__text:FFFFFE00087C1548                                         ; sub_FFFFFE000875FCC8+8BC↑p ...
com.apple.kernel:__text:FFFFFE00087C1548
com.apple.kernel:__text:FFFFFE00087C1548 var_50          = -0x50
com.apple.kernel:__text:FFFFFE00087C1548 var_48          = -0x48
com.apple.kernel:__text:FFFFFE00087C1548 var_40          = -0x40
com.apple.kernel:__text:FFFFFE00087C1548 var_38          = -0x38
com.apple.kernel:__text:FFFFFE00087C1548 var_30          = -0x30
com.apple.kernel:__text:FFFFFE00087C1548 var_28          = -0x28
com.apple.kernel:__text:FFFFFE00087C1548 var_20          = -0x20
com.apple.kernel:__text:FFFFFE00087C1548 var_18          = -0x18
com.apple.kernel:__text:FFFFFE00087C1548 var_10          = -0x10
com.apple.kernel:__text:FFFFFE00087C1548 var_8           = -8
com.apple.kernel:__text:FFFFFE00087C1548 var_s0          =  0
com.apple.kernel:__text:FFFFFE00087C1548 var_s8          =  8
com.apple.kernel:__text:FFFFFE00087C1548
com.apple.kernel:__text:FFFFFE00087C1548                 PACIBSP
com.apple.kernel:__text:FFFFFE00087C154C                 STP             X28, X27, [SP,#-0x10+var_50]!
com.apple.kernel:__text:FFFFFE00087C1550                 STP             X26, X25, [SP,#0x50+var_40]
com.apple.kernel:__text:FFFFFE00087C1554                 STP             X24, X23, [SP,#0x50+var_30]
com.apple.kernel:__text:FFFFFE00087C1558                 STP             X22, X21, [SP,#0x50+var_20]
com.apple.kernel:__text:FFFFFE00087C155C                 STP             X20, X19, [SP,#0x50+var_10]
com.apple.kernel:__text:FFFFFE00087C1560                 STP             X29, X30, [SP,#0x50+var_s0]
com.apple.kernel:__text:FFFFFE00087C1564                 ADD             X29, SP, #0x50
com.apple.kernel:__text:FFFFFE00087C1568                 CBZ             X0, loc_FFFFFE00087C16E0
com.apple.kernel:__text:FFFFFE00087C156C                 MOV             X20, X6
com.apple.kernel:__text:FFFFFE00087C1570                 MOV             X25, X5
com.apple.kernel:__text:FFFFFE00087C1574                 MOV             X26, X4
com.apple.kernel:__text:FFFFFE00087C1578                 MOV             X21, X3
com.apple.kernel:__text:FFFFFE00087C157C                 MOV             X22, X2
com.apple.kernel:__text:FFFFFE00087C1580                 MOV             X23, X1
com.apple.kernel:__text:FFFFFE00087C1584                 MOV             X19, X0
com.apple.kernel:__text:FFFFFE00087C1588                 TBZ             W6, #9, loc_FFFFFE00087C16AC      ; <-- This is the instruction we want to patch
```

The offsets in patch_tss_crash.c are for my macOS build, 15.3.1 (24D70), and if you have any other version, you must modify these offsets to prevent possible damage to your system.

### Building and Running

You can build this project using `make` and run the outputted binary at `build/patch_tss_crash`.
