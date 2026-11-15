/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012208": {
    "elf_va": "0x2208",
    "file_offset": "0x2208",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "0001220c": {
    "elf_va": "0x220c",
    "file_offset": "0x220c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "do_bios_recovery",
      "symbol_va": 9172,
      "symbol_defined": true
    },
    "target_elf_va": "0x23d4",
    "target_function": "do_bios_recovery"
  },
  "00012210": {
    "elf_va": "0x2210",
    "file_offset": "0x2210",
    "raw_u32": "0x44fc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44fc",
    "target_string": "Error while creating the Recovery Thread.\n"
  },
  "00012214": {
    "elf_va": "0x2214",
    "file_offset": "0x2214",
    "raw_u32": "0x163f0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163f0"
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
  
  memset(auStack_10024,0,DAT_00012208);
  iVar1 = pthread_create(&pStack_10028,(pthread_attr_t *)0x0,DAT_0001220c,(void *)0x0);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012210);
    *(undefined4 *)(DAT_00012214 + 0x60) = 0;
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

