/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00014cfc": {
    "elf_va": "0x4cfc",
    "file_offset": "0x4cfc",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00014d00": {
    "elf_va": "0x4d00",
    "file_offset": "0x4d00",
    "raw_u32": "0x5bf0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5bf0",
    "target_string": "Error while Updating the Firmware Image..\n"
  },
  "DAT_or_PTR_00014d04": {
    "elf_va": "0x4d04",
    "file_offset": "0x4d04",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * Speci_Comp_Start_FW_Update
                 (void *param_1,undefined4 param_2,int param_3,undefined4 param_4,undefined4 param_5
                 )

{
  int iVar1;
  undefined4 uStack_20030;
  undefined4 uStack_2002c;
  undefined1 auStack_20028 [2];
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  undefined2 uStack_20020;
  undefined1 auStack_2001e [4];
  undefined1 uStack_2001a;
  undefined1 auStack_20019 [65533];
  undefined1 auStack_1001c [4];
  int iStack_10018;
  
  uStack_20030 = param_4;
  uStack_2002c = param_2;
  memset(auStack_20028,0,DAT_00014cfc);
  memset(auStack_1001c,0,DAT_00014cfc);
  uStack_20024 = param_5;
  uStack_20026 = (undefined1)param_3;
  memcpy(auStack_2001e,&uStack_2002c,4);
  uStack_2001a = 3;
  memcpy(auStack_20019,&uStack_20030,4);
  uStack_20020 = 9;
  if (param_3 == 0xb) {
    iVar1 = send_compmngr_command(auStack_20028,auStack_1001c,600);
    if (iVar1 != 0 || iStack_10018 != 0) goto LAB_00014cb8;
  }
  else {
    iVar1 = send_compmngr_command(auStack_20028,auStack_1001c,0x3c);
    if (iVar1 != 0) {
LAB_00014cb8:
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00014d00);
      iStack_10018 = DAT_00014d04;
      memcpy(param_1,auStack_1001c,DAT_00014cfc);
      return param_1;
    }
  }
  memcpy(param_1,auStack_1001c,DAT_00014cfc);
  return param_1;
}

