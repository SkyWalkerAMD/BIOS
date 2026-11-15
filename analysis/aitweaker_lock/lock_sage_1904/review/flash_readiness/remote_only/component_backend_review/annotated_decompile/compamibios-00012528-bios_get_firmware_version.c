/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00012620": {
    "elf_va": "0x2620",
    "file_offset": "0x2620",
    "raw_u32": "0x4224",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4224",
    "target_string": "bios_get_firmware_version"
  },
  "DAT_or_PTR_00012624": {
    "elf_va": "0x2624",
    "file_offset": "0x2624",
    "raw_u32": "0x4b7",
    "target_elf_va": "0x4b7"
  },
  "DAT_or_PTR_00012628": {
    "elf_va": "0x2628",
    "file_offset": "0x2628",
    "raw_u32": "0x4330",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4330",
    "target_string": "compmngramibios.c"
  },
  "DAT_or_PTR_0001262c": {
    "elf_va": "0x262c",
    "file_offset": "0x262c",
    "raw_u32": "0x4344",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4344",
    "target_string": "[%s:%d][%s]\n"
  },
  "DAT_or_PTR_00012630": {
    "elf_va": "0x2630",
    "file_offset": "0x2630",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00012634": {
    "elf_va": "0x2634",
    "file_offset": "0x2634",
    "raw_u32": "0x4550",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4550",
    "target_string": "Invalid Data length\n"
  },
  "DAT_or_PTR_00012638": {
    "elf_va": "0x2638",
    "file_offset": "0x2638",
    "raw_u32": "0x4568",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4568",
    "target_string": "Failed to get BIOS FW version\n"
  }
}
*/

undefined4 bios_get_firmware_version(undefined2 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 auStack_100a4 [128];
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  undefined1 auStack_1001a [65538];
  undefined1 local_6;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_0001262c,DAT_00012628,DAT_00012624,DAT_00012620);
  memset(auStack_10024,0,DAT_00012630);
  memset(auStack_100a4,0,0x80);
  uVar2 = DAT_00012634;
  if ((param_3 & 0xffff) == 1) {
    local_6 = (undefined1)(param_3 >> 0x10);
    iVar1 = GetBIOSFwVersion(local_6,auStack_100a4);
    uVar2 = DAT_00012638;
    if (iVar1 == 0) {
      memcpy(auStack_1001a,auStack_100a4,0x80);
      uStack_1001c = 0x80;
      goto LAB_000125b4;
    }
  }
  IDBG_LINUXAPP_DbgOut(0x86,uVar2);
  uStack_1001c = 0;
  uStack_10020 = 0xff;
LAB_000125b4:
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

