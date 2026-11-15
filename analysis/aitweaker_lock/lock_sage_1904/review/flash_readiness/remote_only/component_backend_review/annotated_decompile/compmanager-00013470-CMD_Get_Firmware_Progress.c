/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013570": {
    "elf_va": "0x3570",
    "file_offset": "0x3570",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00013574": {
    "elf_va": "0x3574",
    "file_offset": "0x3574",
    "raw_u32": "0x5724",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5724",
    "target_string": " Error while Getting the flash progress..\n"
  },
  "DAT_or_PTR_00013578": {
    "elf_va": "0x3578",
    "file_offset": "0x3578",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * CMD_Get_Firmware_Progress
                 (void *param_1,int param_2,undefined1 param_3,void *param_4,undefined4 param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined2 uStack_20038;
  undefined1 uStack_20036;
  undefined4 uStack_20034;
  undefined2 uStack_20030;
  undefined1 uStack_2002e;
  undefined1 auStack_1002c [4];
  undefined4 uStack_10028;
  ushort uStack_10024;
  undefined1 auStack_10022 [65542];
  
  memset(&uStack_20038,0,DAT_00013570);
  memset(auStack_1002c,0,DAT_00013570);
  if (param_2 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  uStack_20036 = (undefined1)param_2;
  uStack_20034 = param_5;
  uStack_20038 = 6;
  uStack_20030 = 1;
  uStack_2002e = param_3;
  iVar1 = send_compmngr_command(&uStack_20038,auStack_1002c,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013574);
    uStack_10028 = DAT_00013578;
    memcpy(param_1,auStack_1002c,DAT_00013570);
    return param_1;
  }
  memcpy(param_4,auStack_10022,(uint)uStack_10024);
  memcpy(param_1,auStack_1002c,DAT_00013570);
  return param_1;
}

