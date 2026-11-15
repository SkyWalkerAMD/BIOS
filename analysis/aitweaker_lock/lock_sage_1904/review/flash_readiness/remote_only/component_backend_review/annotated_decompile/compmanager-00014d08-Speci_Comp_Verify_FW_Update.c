/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00014e44": {
    "elf_va": "0x4e44",
    "file_offset": "0x4e44",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00014e48": {
    "elf_va": "0x4e48",
    "file_offset": "0x4e48",
    "raw_u32": "0x5c1c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5c1c",
    "target_string": "Error while Verifying the Firmware Image..\n"
  },
  "DAT_or_PTR_00014e4c": {
    "elf_va": "0x4e4c",
    "file_offset": "0x4e4c",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * Speci_Comp_Verify_FW_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
                 ,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_20038;
  undefined4 uStack_20034;
  undefined1 auStack_20030 [2];
  undefined1 uStack_2002e;
  undefined4 uStack_2002c;
  undefined2 uStack_20028;
  undefined1 auStack_20026 [4];
  undefined1 uStack_20022;
  undefined1 auStack_20021 [4];
  undefined1 auStack_2001d [4];
  undefined1 auStack_20019 [65525];
  undefined1 auStack_10024 [4];
  undefined4 uStack_10020;
  
  uVar2 = param_7;
  uStack_20038 = param_4;
  uStack_20034 = param_2;
  memset(auStack_20030,0,DAT_00014e44);
  memset(auStack_10024,0,DAT_00014e44);
  uStack_2002c = uVar2;
  uStack_2002e = (undefined1)param_3;
  memcpy(auStack_20026,&uStack_20034,4);
  uStack_20022 = 4;
  memcpy(auStack_20021,&uStack_20038,4);
  memcpy(auStack_2001d,&param_5,4);
  memcpy(auStack_20019,&param_6,4);
  if (param_3 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  uStack_20028 = 0x11;
  iVar1 = send_compmngr_command(auStack_20030,auStack_10024,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014e48);
    uStack_10020 = DAT_00014e4c;
    memcpy(param_1,auStack_10024,DAT_00014e44);
    return param_1;
  }
  memcpy(param_1,auStack_10024,DAT_00014e44);
  return param_1;
}

