// for macOS 24D70

#include <capstone.h>
#include <libkextrw.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SUB_THREAD_SET_STATE_INTERNAL kslide(0xFFFFFE00087C1548)
#define SUB_THREAD_SET_STATE_INTERNAL_TBZ_ENTITLEMENT_CHECK_OFFSET 0x40

int main(void) {

  // Show confirmation message that requires user input
  printf(
      "This program will patch the kernel in memory. ARE YOU SURE THE OFFSETS "
      "ARE CORRECT? Note that the patch is not permanent and will not persist "
      "upon reboots. (y/n): ");
  char response;
  scanf(" %c", &response);
  if (response != 'y' && response != 'Y') {
    printf("Operation cancelled.\n");
    return 0;
  }

  if (kextrw_init() == -1) {
    printf("Failed to initialize KextRW\n");
    return 1;
  }

  uint64_t kernelBase = get_kernel_base();
  if (kernelBase == 0) {
    printf("Failed to get kernel base\n");
    kextrw_deinit();
    return 1;
  }

  printf("Kernel base: 0x%llx\n", kernelBase);

  uint64_t pc = SUB_THREAD_SET_STATE_INTERNAL +
                SUB_THREAD_SET_STATE_INTERNAL_TBZ_ENTITLEMENT_CHECK_OFFSET;

  uint32_t orig_instruction = kread32(pc);

  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
    printf("Failed to initialize Capstone\n");
    kextrw_deinit();
    return 1;
  }

  count = cs_disasm(handle, (uint8_t *)&orig_instruction, 4, pc, 1, &insn);

  if (count > 0) {
    // Extract the target address from the operand
    const char *mnemonic = insn[0].mnemonic; // Should be "tbz"
    if (strcmp(mnemonic, "tbz") != 0) {
      printf("Expected 'tbz' instruction, found '%s'\n", mnemonic);
      cs_free(insn, count);
      cs_close(&handle);
      kextrw_deinit();
      return 1;
    }

    // Parse operands to get the target address
    const char *op_str = insn[0].op_str; // Example: "w6, #9, #0x16d9eeee4"
    printf("Disassembled instruction: %s\t%s\n", mnemonic, op_str);

    // Extract target address using sscanf
    char reg_name[16];
    int bit_number;
    uint64_t target_address = 0;

    int num_parsed = sscanf(op_str, "%[^,], #%d, #0x%llx", reg_name,
                            &bit_number, &target_address);

    if (num_parsed != 3) {
      printf("Failed to parse operands: '%s'\n", op_str);
      cs_free(insn, count);
      cs_close(&handle);
      kextrw_deinit();
      return 1;
    }

    printf("Parsed operands: reg=%s, bit=%d, target=0x%llx\n", reg_name,
           bit_number, target_address);

    // Compute the offset for the B instruction
    int64_t offset = target_address - pc;

    // Ensure offset is word-aligned
    if (offset % 4 != 0) {
      printf("Error: target address is not word-aligned\n");
      cs_free(insn, count);
      cs_close(&handle);
      kextrw_deinit();
      return 1;
    }

    int32_t imm26 = (offset >> 2) & 0x03FFFFFF;

    uint32_t B_opcode = 0b000101;
    uint32_t new_instruction = (B_opcode << 26) | (imm26 & 0x03FFFFFF);

    printf("Original instruction: 0x%08x\n", orig_instruction);
    printf("New instruction: 0x%08x\n", new_instruction);

    printf("Now patching... If the process hangs, you need to disable SIP "
           "in recovery mode");

    kwrite32(pc, new_instruction);

    // Verify the patch
    uint32_t patched_instruction = kread32(pc);
    if (patched_instruction != new_instruction) {
      printf("Failed to patch instruction at 0x%llx: expected 0x%08x, got "
             "0x%08x\n",
             pc, new_instruction, patched_instruction);
      cs_free(insn, count);
      cs_close(&handle);
      kextrw_deinit();
      return 1;
    }

    printf("Successfully patched instruction at 0x%llx\n", pc);

    cs_free(insn, count);
    cs_close(&handle);
  } else {
    printf("Failed to disassemble instruction\n");
    cs_close(&handle);
    kextrw_deinit();
    return 1;
  }

  kextrw_deinit();
  return 0;
}
