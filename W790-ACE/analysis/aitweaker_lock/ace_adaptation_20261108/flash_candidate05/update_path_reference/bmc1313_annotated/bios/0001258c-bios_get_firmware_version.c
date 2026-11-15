/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012684": {
    "elf_va": "0x2684",
    "file_offset": "0x2684",
    "raw_u32": "0x43cc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43cc",
    "target_string": "bios_get_firmware_version"
  },
  "00012688": {
    "elf_va": "0x2688",
    "file_offset": "0x2688",
    "raw_u32": "0x50a",
    "target_elf_va": "0x50a"
  },
  "0001268c": {
    "elf_va": "0x268c",
    "file_offset": "0x268c",
    "raw_u32": "0x4488",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4488",
    "target_string": "compmngramibios.c"
  },
  "00012690": {
    "elf_va": "0x2690",
    "file_offset": "0x2690",
    "raw_u32": "0x449c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x449c",
    "target_string": "[%s:%d][%s]\n"
  },
  "00012694": {
    "elf_va": "0x2694",
    "file_offset": "0x2694",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00012698": {
    "elf_va": "0x2698",
    "file_offset": "0x2698",
    "raw_u32": "0x46a8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x46a8",
    "target_string": "Invalid Data length\n"
  },
  "0001269c": {
    "elf_va": "0x269c",
    "file_offset": "0x269c",
    "raw_u32": "0x46c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x46c0",
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
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00012690,DAT_0001268c,DAT_00012688,DAT_00012684);
  memset(auStack_10024,0,DAT_00012694);
  memset(auStack_100a4,0,0x80);
  uVar2 = DAT_00012698;
  if ((param_3 & 0xffff) == 1) {
    local_6 = (undefined1)(param_3 >> 0x10);
    iVar1 = GetBIOSFwVersion(local_6,auStack_100a4);
    uVar2 = DAT_0001269c;
    if (iVar1 == 0) {
      memcpy(auStack_1001a,auStack_100a4,0x80);
      uStack_1001c = 0x80;
      goto LAB_00012618;
    }
  }
  IDBG_LINUXAPP_DbgOut(0x86,uVar2);
  uStack_1001c = 0;
  uStack_10020 = 0xff;
LAB_00012618:
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

