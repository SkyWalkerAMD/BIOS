/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013fa4": {
    "elf_va": "0x3fa4",
    "file_offset": "0x3fa4",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "gFlashInfo",
      "symbol_va": 91316,
      "symbol_defined": true
    },
    "target_elf_va": "0x164b4"
  },
  "00013fa8": {
    "elf_va": "0x3fa8",
    "file_offset": "0x3fa8",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00013fac": {
    "elf_va": "0x3fac",
    "file_offset": "0x3fac",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00013fb0": {
    "elf_va": "0x3fb0",
    "file_offset": "0x3fb0",
    "raw_u32": "0x443c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x443c",
    "target_string": "bios_start_update"
  },
  "00013fb4": {
    "elf_va": "0x3fb4",
    "file_offset": "0x3fb4",
    "raw_u32": "0x501c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x501c",
    "target_string": "[%s] FlashOffset = 0x%x, SizetoWrite = 0x%x, SectionFlash = %d\n"
  },
  "00013fb8": {
    "elf_va": "0x3fb8",
    "file_offset": "0x3fb8",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_corefeatures",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00013fbc": {
    "elf_va": "0x3fbc",
    "file_offset": "0x3fbc",
    "raw_u32": "0x4e6c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4e6c",
    "target_string": "[%s] FlashOffset = 0x%x, Size = 0x%x\n"
  },
  "00013fc0": {
    "elf_va": "0x3fc0",
    "file_offset": "0x3fc0",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "bios_flash",
      "symbol_va": 14332,
      "symbol_defined": true
    },
    "target_elf_va": "0x37fc",
    "target_function": "bios_flash"
  },
  "00013fc4": {
    "elf_va": "0x3fc4",
    "file_offset": "0x3fc4",
    "raw_u32": "0x5174",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5174",
    "target_string": "Error while creating the BIOS Update Thread.\n"
  },
  "00013fc8": {
    "elf_va": "0x3fc8",
    "file_offset": "0x3fc8",
    "raw_u32": "0x3d1",
    "target_elf_va": "0x3d1"
  },
  "00013fcc": {
    "elf_va": "0x3fcc",
    "file_offset": "0x3fcc",
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
  "00013fd0": {
    "elf_va": "0x3fd0",
    "file_offset": "0x3fd0",
    "raw_u32": "0x505c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x505c",
    "target_string": "[%s:%d]Failed in getting bios file size \n"
  },
  "00013fd4": {
    "elf_va": "0x3fd4",
    "file_offset": "0x3fd4",
    "raw_u32": "0x5158",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5158",
    "target_string": "Skip BiosConfiguration...\n"
  },
  "00013fd8": {
    "elf_va": "0x3fd8",
    "file_offset": "0x3fd8",
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
  "00013fdc": {
    "elf_va": "0x3fdc",
    "file_offset": "0x3fdc",
    "raw_u32": "0x50b0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x50b0",
    "target_string": "signed image verification success"
  },
  "00013fe0": {
    "elf_va": "0x3fe0",
    "file_offset": "0x3fe0",
    "raw_u32": "0x3f5",
    "target_elf_va": "0x3f5"
  },
  "00013fe4": {
    "elf_va": "0x3fe4",
    "file_offset": "0x3fe4",
    "raw_u32": "0x50fc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x50fc",
    "target_string": "[%s:%d]Bios file size exceeds the max size allowed \n"
  },
  "00013fe8": {
    "elf_va": "0x3fe8",
    "file_offset": "0x3fe8",
    "raw_u32": "0x3db",
    "target_elf_va": "0x3db"
  },
  "00013fec": {
    "elf_va": "0x3fec",
    "file_offset": "0x3fec",
    "raw_u32": "0x5088",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5088",
    "target_string": "[%s:%d]Signed Image verification failed"
  },
  "00013ff0": {
    "elf_va": "0x3ff0",
    "file_offset": "0x3ff0",
    "raw_u32": "0x5134",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5134",
    "target_string": "[%s:%d]Bios Configuration Failed\n"
  },
  "00013ff4": {
    "elf_va": "0x3ff4",
    "file_offset": "0x3ff4",
    "raw_u32": "0x3e7",
    "target_elf_va": "0x3e7"
  },
  "00013ff8": {
    "elf_va": "0x3ff8",
    "file_offset": "0x3ff8",
    "raw_u32": "0x50d4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x50d4",
    "target_string": "[%s:%d]Failed in getting hash length \n"
  }
}
*/

undefined4
bios_start_update(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 *__arg;
  size_t __n;
  __start_routine *__start_routine;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  pthread_t pStack_10054;
  uint uStack_10050;
  undefined4 uStack_1004c;
  uint uStack_10048;
  int iStack_10044;
  int iStack_10040;
  undefined2 auStack_1003c [2];
  int iStack_10038;
  undefined2 uStack_10034;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  __n = DAT_00013fa8;
  puVar1 = DAT_00013fa4;
  uStack_10050 = 0;
  uStack_1004c = 0;
  uStack_10048 = 0;
  iStack_10044 = 0;
  *DAT_00013fa4 = 0;
  puVar1[1] = 0;
  puVar1[2] = 0;
  puVar1[3] = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_1003c,0,__n);
  memcpy(&iStack_10040,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10040 == *DAT_00013fac) {
    memcpy(&uStack_1004c,(void *)((int)&uStack_4 + 2),4);
    memcpy(&uStack_10048,&stack0x00000002,4);
    memcpy(&iStack_10044,&stack0x00000006,4);
    iVar4 = iStack_10044;
    uVar3 = uStack_10048;
    uVar2 = uStack_1004c;
    uVar8 = uStack_10048;
    iVar9 = iStack_10044;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fb4,DAT_00013fb0,uStack_1004c,uStack_10048,iStack_10044);
    iVar5 = get_bios_file_size(&uStack_10050);
    uVar6 = DAT_00013fd0;
    uVar7 = DAT_00013fc8;
    if (iVar5 == 0) {
      if (*(int *)(DAT_00013fb8 + 0x34) == 1) {
        iVar5 = VerifyImageSign(1,DAT_00013fd8,0);
        if (iVar5 != 0) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00013fec,DAT_00013fcc,DAT_00013fe8,uVar8,iVar9);
          uStack_10034 = 0;
          iStack_10038 = 0xff;
          goto LAB_00013d68;
        }
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fdc);
        iVar5 = GetHashLength(DAT_00013fd8);
        uVar6 = DAT_00013ff8;
        uVar7 = DAT_00013ff4;
        if (iVar5 == -1) goto LAB_00013ecc;
        if (iVar5 == 0) {
          uStack_10050 = uStack_10050 - 0x88;
        }
      }
      uVar6 = DAT_00013fe4;
      uVar7 = DAT_00013fe0;
      if (uVar3 < uStack_10050) {
LAB_00013f44:
        IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00013fcc,uVar7,uVar8,iVar9);
        iStack_10038 = 0xff;
        uStack_10034 = 0;
      }
      else {
        if (iVar4 == 0xff) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fd4);
        }
        else {
          iVar5 = BiosConfiguration();
          if (iVar5 != 0) {
            uVar6 = DAT_00013ff0;
            uVar7 = 0x400;
            goto LAB_00013f44;
          }
        }
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fbc,DAT_00013fb0,uVar2,uStack_10050);
        __start_routine = DAT_00013fc0;
        __arg = DAT_00013fa4;
        *puVar1 = uVar2;
        puVar1[2] = iVar4;
        puVar1[1] = uStack_10050;
        puVar1[3] = param_2;
        iStack_10038 = pthread_create(&pStack_10054,(pthread_attr_t *)0x0,__start_routine,__arg);
        if (iStack_10038 == 0) {
          uStack_10034 = 0;
          goto LAB_00013d70;
        }
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fc4);
        uStack_10034 = 0;
      }
    }
    else {
LAB_00013ecc:
      IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00013fcc,uVar7,uVar8,iVar9);
      uStack_10034 = 0;
      iStack_10038 = 0xff;
    }
  }
  else {
    iStack_10038 = 6;
  }
LAB_00013d68:
  ActiveHostSPIDriver(1);
LAB_00013d70:
  auStack_1003c[0] = param_1;
  send_compmngr_response(auStack_1003c);
  return 0;
}

