// for macOS 25A5306g

#include <capstone.h>
#include <libkextrw.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// base FFFFFE0008869F9C
// tbnz FFFFFE0008869FE0
// tbz FFFFFE0008869FE8

#define SUB_THREAD_SET_STATE_INTERNAL kslide(0xFFFFFE0008869F9C)
#define OFFSET_TBNZ_ENTITLEMENT_CHECK 0x44 /* TBNZ  W6,#9  */
#define OFFSET_TBZ_THREAD_FLAG 0x4C        /* TBZ   W8,#31 */

#define ARM64_NOP 0xD503201F /* official NOP */

/* ----------------------------------------------------------- */

static bool patch_tbnz_to_nop(csh handle, uint64_t pc) {
  printf("🔍 Patching TBNZ to NOP at 0x%llx\n", pc);

  uint32_t original = kread32(pc);

  cs_insn *insn = NULL;
  size_t n = cs_disasm(handle, (uint8_t *)&original, 4, pc, 1, &insn);
  if (n != 1 || insn[0].id != ARM64_INS_TBNZ) {
    printf("    ❌ Expected TBNZ at 0x%llx, found “%s”\n", pc,
           n ? insn[0].mnemonic : "???");
    cs_free(insn, n);
    return false;
  }

  printf("    🌀 Patching TBNZ @0x%llx => NOP\n", pc);
  kwrite32(pc, ARM64_NOP);

  bool ok = (kread32(pc) == ARM64_NOP);
  puts(ok ? "    😎 Patch OK" : "    ❌ Verification failed");
  cs_free(insn, n);
  return ok;
}

static bool patch_tbz_to_b(csh handle, uint64_t pc) {
  printf("🔍 Patching TBZ to B at 0x%llx\n", pc);

  uint32_t original = kread32(pc);

  cs_insn *insn = NULL;
  size_t n = cs_disasm(handle, (uint8_t *)&original, 4, pc, 1, &insn);
  if (n != 1 || insn[0].id != ARM64_INS_TBZ) {
    printf("     ❌ Expected TBZ at 0x%llx, found “%s”\n", pc,
           n ? insn[0].mnemonic : "???");
    cs_free(insn, n);
    return false;
  }

  const cs_arm64 *a64 = &insn[0].detail->arm64;
  if (a64->op_count < 3 || a64->operands[2].type != ARM64_OP_IMM) {
    puts("    ❌ Capstone did not supply a branch target");
    cs_free(insn, n);
    return false;
  }

  uint64_t target = (uint64_t)a64->operands[2].imm;
  int64_t offset = (int64_t)target - (int64_t)pc;
  if (offset & 3) {
    printf("    ❌ Target 0x%llx is not word-aligned\n", target);
    cs_free(insn, n);
    return false;
  }

  uint32_t imm26 = ((uint32_t)(offset >> 2)) & 0x03FFFFFF;
  uint32_t branch = (0b000101u << 26) | imm26; /* B target */

  printf("    🌀 Patching TBZ @0x%llx => B 0x%llx (0x%08x)\n", pc, target,
         branch);

  kwrite32(pc, branch);
  bool ok = (kread32(pc) == branch);
  puts(ok ? "    😎 Patch OK" : "    ❌ Verification failed");
  cs_free(insn, n);
  return ok;
}

int main(void) {
  printf("thread_set_state entitlement bypass\n"
         "Changes vanish on reboot. Proceed?  (y/N): ");
  char reply = 0;
  scanf(" %c", &reply);
  if (reply != 'y' && reply != 'Y') {
    puts("📭 Cancelled.");
    return 0;
  }

  if (kextrw_init() == -1) {
    puts("❌ KextRW init failed");
    return 1;
  }

  uint64_t kbase = get_kernel_base();
  if (!kbase) {
    puts("❌ Couldn’t find kernel base");
    kextrw_deinit();
    return 1;
  }

  printf("🍦 Kernel base: 0x%llx (slide: 0x%llx)\n", kbase, gKernelSlide);

  csh handle;
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
    puts("❌ Capstone init failed");
    kextrw_deinit();
    return 1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  bool ok1 = patch_tbnz_to_nop(handle, SUB_THREAD_SET_STATE_INTERNAL +
                                           OFFSET_TBNZ_ENTITLEMENT_CHECK);
  bool ok2 = patch_tbz_to_b(handle, SUB_THREAD_SET_STATE_INTERNAL +
                                        OFFSET_TBZ_THREAD_FLAG);

  cs_close(&handle);
  kextrw_deinit();

  if (ok1 && ok2) {
    puts("🎉 All patches applied successfully!");
    return 0;
  }
  puts("💔 One or more patches failed.");
  return 1;
}
