/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000137dc": {
    "elf_va": "0x37dc",
    "file_offset": "0x37dc",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "gFlashInfo",
      "symbol_va": 91316,
      "symbol_defined": true
    },
    "target_elf_va": "0x164b4"
  },
  "000137e0": {
    "elf_va": "0x37e0",
    "file_offset": "0x37e0",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "000137e4": {
    "elf_va": "0x37e4",
    "file_offset": "0x37e4",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "000137e8": {
    "elf_va": "0x37e8",
    "file_offset": "0x37e8",
    "raw_u32": "0x4408",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4408",
    "target_string": "bios_verify_comp"
  },
  "000137ec": {
    "elf_va": "0x37ec",
    "file_offset": "0x37ec",
    "raw_u32": "0x4e10",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4e10",
    "target_string": "[%s]FlashOffset = 0x%x, Size = 0x%x\n"
  },
  "000137f0": {
    "elf_va": "0x37f0",
    "file_offset": "0x37f0",
    "raw_u32": "0x164a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a0"
  },
  "000137f4": {
    "elf_va": "0x37f4",
    "file_offset": "0x37f4",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "bios_verify_flash",
      "symbol_va": 16468,
      "symbol_defined": true
    },
    "target_elf_va": "0x4054",
    "target_function": "bios_verify_flash"
  },
  "000137f8": {
    "elf_va": "0x37f8",
    "file_offset": "0x37f8",
    "raw_u32": "0x4e38",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4e38",
    "target_string": "Error while creating the BIOS Verify Flash Thread.\n"
  }
}
*/

undefined4
bios_verify_comp(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *__arg;
  size_t __n;
  undefined4 uVar1;
  undefined4 uVar2;
  pthread_t pStack_10044;
  undefined4 uStack_10040;
  undefined4 uStack_1003c;
  int iStack_10038;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  __arg = DAT_000137dc;
  *DAT_000137dc = 0;
  __n = DAT_000137e0;
  __arg[1] = 0;
  __arg[2] = 0;
  __arg[3] = 0;
  uStack_10040 = 0;
  uStack_1003c = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_10034,0,__n);
  memcpy(&iStack_10038,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10038 == *DAT_000137e4) {
    memcpy(&uStack_10040,(void *)((int)&uStack_4 + 2),4);
    memcpy(&uStack_1003c,&stack0x00000002,4);
    uVar2 = uStack_1003c;
    uVar1 = uStack_10040;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000137ec,DAT_000137e8,uStack_10040,uStack_1003c);
    __arg[3] = param_2;
    *__arg = uVar1;
    __arg[1] = uVar2;
    get_bios_file_size(__arg + 1);
    if (*DAT_000137f0 == -1) {
      uStack_1002c = 0;
      iStack_10030 = -1;
    }
    else {
      iStack_10030 = pthread_create(&pStack_10044,(pthread_attr_t *)0x0,DAT_000137f4,__arg);
      if (iStack_10030 == 0) {
        uStack_1002c = 0;
        goto LAB_000136ec;
      }
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000137f8);
      uStack_1002c = 0;
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_000136ec:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

