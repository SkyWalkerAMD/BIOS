/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_0001389c": {
    "elf_va": "0x389c",
    "file_offset": "0x389c",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_000138a0": {
    "elf_va": "0x38a0",
    "file_offset": "0x38a0",
    "raw_u32": "0x5784",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5784",
    "target_string": " Error while getting the BIOS firmware version..\n"
  },
  "DAT_or_PTR_000138a4": {
    "elf_va": "0x38a4",
    "file_offset": "0x38a4",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * CMD_Get_BIOSFirmware_Version(void *param_1,undefined1 param_2)

{
  int iVar1;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined2 uStack_20020;
  undefined1 uStack_2001e;
  undefined1 auStack_1001c [4];
  undefined4 uStack_10018;
  
  memset(&uStack_20028,0,DAT_0001389c);
  memset(auStack_1001c,0,DAT_0001389c);
  uStack_20028 = 0xc;
  uStack_20026 = 2;
  uStack_20020 = 1;
  uStack_2001e = param_2;
  iVar1 = send_compmngr_command(&uStack_20028,auStack_1001c,0x3c);
  if (iVar1 == 0) {
    memcpy(param_1,auStack_1001c,DAT_0001389c);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_000138a0);
  uStack_10018 = DAT_000138a4;
  memcpy(param_1,auStack_1001c,DAT_0001389c);
  return param_1;
}

