/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00014f94": {
    "elf_va": "0x4f94",
    "file_offset": "0x4f94",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00014f98": {
    "elf_va": "0x4f98",
    "file_offset": "0x4f98",
    "raw_u32": "0x5c74",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5c74",
    "target_string": "Buffer Overflow occurs..\n"
  },
  "DAT_or_PTR_00014f9c": {
    "elf_va": "0x4f9c",
    "file_offset": "0x4f9c",
    "raw_u32": "0x5c48",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5c48",
    "target_string": "Error while Getting the flash progress..\n"
  },
  "DAT_or_PTR_00014fa0": {
    "elf_va": "0x4fa0",
    "file_offset": "0x4fa0",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * Speci_Comp_Get_Update_Progress
                 (void *param_1,undefined4 param_2,int param_3,undefined1 param_4,void *param_5,
                 undefined4 param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uStack_20034;
  undefined1 auStack_20030 [2];
  undefined1 uStack_2002e;
  undefined4 uStack_2002c;
  undefined2 uStack_20028;
  undefined1 auStack_20026 [4];
  undefined1 uStack_20022;
  undefined1 uStack_20021;
  undefined1 auStack_10024 [4];
  undefined4 uStack_10020;
  ushort uStack_1001c;
  undefined1 auStack_1001a [65542];
  
  uStack_20034 = param_2;
  memset(auStack_20030,0,DAT_00014f94);
  memset(auStack_10024,0,DAT_00014f94);
  uStack_2002c = param_6;
  uStack_2002e = (undefined1)param_3;
  memcpy(auStack_20026,&uStack_20034,4);
  if (param_3 == 0xb) {
    uVar2 = 600;
  }
  else {
    uVar2 = 0x3c;
  }
  uStack_20022 = 6;
  uStack_20028 = 6;
  uStack_20021 = param_4;
  iVar1 = send_compmngr_command(auStack_20030,auStack_10024,uVar2);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014f9c);
    uStack_10020 = DAT_00014fa0;
    memcpy(param_1,auStack_10024,DAT_00014f94);
    return param_1;
  }
  if (uStack_1001c < 5) {
    memcpy(param_5,auStack_1001a,(uint)uStack_1001c);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014f98);
  }
  memcpy(param_1,auStack_10024,DAT_00014f94);
  return param_1;
}

