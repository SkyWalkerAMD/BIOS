/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013720": {
    "elf_va": "0x3720",
    "file_offset": "0x3720",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00013724": {
    "elf_va": "0x3724",
    "file_offset": "0x3724",
    "raw_u32": "0x4f74",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4f74",
    "target_string": "Error while verify BIOS signature\n"
  },
  "00013728": {
    "elf_va": "0x3728",
    "file_offset": "0x3728",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * CMD_Verify_BIOS_Signature(void *param_1)

{
  int iVar1;
  undefined2 uStack_20020;
  undefined1 uStack_2001e;
  undefined1 auStack_10014 [4];
  undefined4 uStack_10010;
  
  memset(&uStack_20020,0,DAT_00013720);
  memset(auStack_10014,0,DAT_00013720);
  uStack_20020 = 0xb;
  uStack_2001e = 2;
  iVar1 = send_compmngr_command(&uStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_10014,DAT_00013720);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013724);
  uStack_10010 = DAT_00013728;
  memcpy(param_1,auStack_10014,DAT_00013720);
  return param_1;
}

