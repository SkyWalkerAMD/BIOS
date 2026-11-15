/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000137e0": {
    "elf_va": "0x37e0",
    "file_offset": "0x37e0",
    "raw_u32": "0x16460",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16460"
  },
  "DAT_or_PTR_000137e4": {
    "elf_va": "0x37e4",
    "file_offset": "0x37e4",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_000137e8": {
    "elf_va": "0x37e8",
    "file_offset": "0x37e8",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_000137ec": {
    "elf_va": "0x37ec",
    "file_offset": "0x37ec",
    "raw_u32": "0x4938",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4938",
    "target_string": "/var/bios.bin"
  },
  "DAT_or_PTR_000137f0": {
    "elf_va": "0x37f0",
    "file_offset": "0x37f0",
    "raw_u32": "0x4c28",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c28",
    "target_string": "write memory exceed the allocated size, OffSet: %d Length: %d g_AllocatedImageSize: %d\n"
  },
  "DAT_or_PTR_000137f4": {
    "elf_va": "0x37f4",
    "file_offset": "0x37f4",
    "raw_u32": "0x4c80",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c80",
    "target_string": "Error while uploading the BIOS Image OffSet: %d Length: %d"
  },
  "DAT_or_PTR_000137f8": {
    "elf_va": "0x37f8",
    "file_offset": "0x37f8",
    "raw_u32": "0x4c14",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c14",
    "target_string": "/var/biossig.bin"
  },
  "DAT_or_PTR_000137fc": {
    "elf_va": "0x37fc",
    "file_offset": "0x37fc",
    "raw_u32": "0x4cbc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4cbc",
    "target_string": "Error while uploading the BIOS Signature Image OffSet: %d Length: %d"
  }
}
*/

undefined4
bios_upload_comp(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iStack_1003c;
  int iStack_10038;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iVar1 = DAT_000137e0;
  iStack_10038 = 0;
  iVar4 = *(int *)(DAT_000137e0 + 8);
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_10034,0,DAT_000137e4);
  memcpy(&iStack_1003c,(void *)((int)&uStack_8 + 2),4);
  if (iStack_1003c == *DAT_000137e8) {
    memcpy(&iStack_10038,(void *)((int)&uStack_4 + 2),4);
    iVar2 = iStack_10038;
    if (*(uint *)(iVar1 + 0x10) < (uint)(iStack_10038 + iVar4)) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000137f0,iVar4,iStack_10038);
      uStack_1002c = 0;
      iStack_10030 = 0xff;
    }
    else if ((iVar4 == 0) && (*(int *)(iVar1 + 0xc) == 1)) {
      iVar4 = file_write_data(DAT_000137ec,&stack0x00001002,0,iStack_10038 + -0x1000);
      if (iVar4 == 0) {
        iVar4 = file_write_data(DAT_000137f8,&stack0x00000002,0,0x1000);
        if (iVar4 == 0) goto LAB_000136ec;
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000137fc,0,iVar2);
        uStack_1002c = 0;
        iStack_10030 = 0xff;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000137f4,0,iVar2);
        uStack_1002c = 0;
        iStack_10030 = 0xff;
      }
    }
    else {
      iVar3 = file_write_data(DAT_000137ec,&stack0x00000002,iVar4,iStack_10038);
      if (iVar3 == 0) {
LAB_000136ec:
        *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + iVar2;
        if (iStack_10030 == 0) goto LAB_00013660;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000137f4,iVar4,iVar2);
        iStack_10030 = 0xff;
        uStack_1002c = 0;
      }
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_00013660:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

