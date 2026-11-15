/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00012ee8": {
    "elf_va": "0x2ee8",
    "file_offset": "0x2ee8",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00012eec": {
    "elf_va": "0x2eec",
    "file_offset": "0x2eec",
    "raw_u32": "0x55f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x55f8",
    "target_string": "/var/block_chassis_ops"
  },
  "DAT_or_PTR_00012ef0": {
    "elf_va": "0x2ef0",
    "file_offset": "0x2ef0",
    "raw_u32": "0x5638",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5638",
    "target_string": "Error while exiting into fimware update mode\n"
  },
  "DAT_or_PTR_00012ef4": {
    "elf_va": "0x2ef4",
    "file_offset": "0x2ef4",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * CMD_Exit_FW_Update_mode(void *param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uStack_20024;
  undefined2 auStack_20020 [4];
  undefined2 uStack_20018;
  undefined1 auStack_20016 [65538];
  undefined1 auStack_10014 [4];
  int iStack_10010;
  
  uStack_20024 = param_2;
  memset(auStack_20020,0,DAT_00012ee8);
  memset(auStack_10014,0,DAT_00012ee8);
  auStack_20020[0] = 2;
  uStack_20018 = 4;
  memcpy(auStack_20016,&uStack_20024,4);
  iVar1 = send_compmngr_command(auStack_20020,auStack_10014,0x3c);
  if (iVar1 == 0) {
    if (iStack_10010 == 0) {
      unlink(DAT_00012eec);
    }
    memcpy(param_1,auStack_10014,DAT_00012ee8);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012ef0);
  iStack_10010 = DAT_00012ef4;
  memcpy(param_1,auStack_10014,DAT_00012ee8);
  return param_1;
}

