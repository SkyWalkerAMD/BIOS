/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013648": {
    "elf_va": "0x3648",
    "file_offset": "0x3648",
    "raw_u32": "0x164a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a0"
  },
  "0001364c": {
    "elf_va": "0x364c",
    "file_offset": "0x364c",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00013650": {
    "elf_va": "0x3650",
    "file_offset": "0x3650",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00013654": {
    "elf_va": "0x3654",
    "file_offset": "0x3654",
    "raw_u32": "0x4d10",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d10",
    "target_string": "/var/bios.bin"
  },
  "00013658": {
    "elf_va": "0x3658",
    "file_offset": "0x3658",
    "raw_u32": "0x4d34",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d34",
    "target_string": "write memory exceed the allocated size, OffSet: %d Length: %d g_AllocatedImageSize: %d\n"
  },
  "0001365c": {
    "elf_va": "0x365c",
    "file_offset": "0x365c",
    "raw_u32": "0x4d8c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d8c",
    "target_string": "Error while uploading the BIOS Image OffSet: %d Length: %d"
  },
  "00013660": {
    "elf_va": "0x3660",
    "file_offset": "0x3660",
    "raw_u32": "0x4d20",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d20",
    "target_string": "/var/biossig.bin"
  },
  "00013664": {
    "elf_va": "0x3664",
    "file_offset": "0x3664",
    "raw_u32": "0x4dc8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4dc8",
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
  
  iVar1 = DAT_00013648;
  iStack_10038 = 0;
  iVar4 = *(int *)(DAT_00013648 + 8);
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_10034,0,DAT_0001364c);
  memcpy(&iStack_1003c,(void *)((int)&uStack_8 + 2),4);
  if (iStack_1003c == *DAT_00013650) {
    memcpy(&iStack_10038,(void *)((int)&uStack_4 + 2),4);
    iVar2 = iStack_10038;
    if (*(uint *)(iVar1 + 0x10) < (uint)(iStack_10038 + iVar4)) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013658,iVar4,iStack_10038);
      uStack_1002c = 0;
      iStack_10030 = 0xff;
    }
    else if ((iVar4 == 0) && (*(int *)(iVar1 + 0xc) == 1)) {
      iVar4 = file_write_data(DAT_00013654,&stack0x00001002,0,iStack_10038 + -0x1000);
      if (iVar4 == 0) {
        iVar4 = file_write_data(DAT_00013660,&stack0x00000002,0,0x1000);
        if (iVar4 == 0) goto LAB_00013554;
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013664,0,iVar2);
        uStack_1002c = 0;
        iStack_10030 = 0xff;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_0001365c,0,iVar2);
        uStack_1002c = 0;
        iStack_10030 = 0xff;
      }
    }
    else {
      iVar3 = file_write_data(DAT_00013654,&stack0x00000002,iVar4,iStack_10038);
      if (iVar3 == 0) {
LAB_00013554:
        *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + iVar2;
        if (iStack_10030 == 0) goto LAB_000134c8;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_0001365c,iVar4,iVar2);
        iStack_10030 = 0xff;
        uStack_1002c = 0;
      }
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_000134c8:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

