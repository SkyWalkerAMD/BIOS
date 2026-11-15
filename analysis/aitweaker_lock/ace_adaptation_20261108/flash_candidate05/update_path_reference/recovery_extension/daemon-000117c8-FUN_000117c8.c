/* Exact ELF literal/relocation map. */
{
  "00011870": {
    "elf_va": "0x11870",
    "file_offset": "0x1870",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00011874": {
    "elf_va": "0x11874",
    "file_offset": "0x1874",
    "raw_u32": "0x120a0",
    "target_elf_va": "0x120a0",
    "target_string": "Clear CompBook: Command Length Invalid"
  }
}

undefined4 FUN_000117c8(undefined2 param_1,undefined4 param_2,uint param_3)

{
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  undefined1 local_6;
  
  memset(auStack_10024,0,DAT_00011870);
  if ((param_3 & 0xffff) == 1) {
    local_6 = (undefined1)(param_3 >> 0x10);
    Clear_CompBook_Repos(local_6);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011874);
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

