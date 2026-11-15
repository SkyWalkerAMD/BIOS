/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000121a4": {
    "elf_va": "0x21a4",
    "file_offset": "0x21a4",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_000121a8": {
    "elf_va": "0x21a8",
    "file_offset": "0x21a8",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "do_bios_recovery",
      "symbol_va": 9072,
      "symbol_defined": true
    },
    "target_elf_va": "0x2370",
    "target_function": "do_bios_recovery"
  },
  "DAT_or_PTR_000121ac": {
    "elf_va": "0x21ac",
    "file_offset": "0x21ac",
    "raw_u32": "0x43a4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43a4",
    "target_string": "Error while creating the Recovery Thread.\n"
  },
  "DAT_or_PTR_000121b0": {
    "elf_va": "0x21b0",
    "file_offset": "0x21b0",
    "raw_u32": "0x163e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163e8"
  }
}
*/

undefined4 bios_perform_recovery(undefined2 param_1)

{
  int iVar1;
  pthread_t pStack_10028;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  memset(auStack_10024,0,DAT_000121a4);
  iVar1 = pthread_create(&pStack_10028,(pthread_attr_t *)0x0,DAT_000121a8,(void *)0x0);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000121ac);
    *(undefined4 *)(DAT_000121b0 + 0x70) = 0;
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

