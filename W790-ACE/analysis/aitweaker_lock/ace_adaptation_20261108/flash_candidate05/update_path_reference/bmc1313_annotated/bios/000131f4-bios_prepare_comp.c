/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013418": {
    "elf_va": "0x3418",
    "file_offset": "0x3418",
    "raw_u32": "0x43f4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43f4",
    "target_string": "bios_prepare_comp"
  },
  "0001341c": {
    "elf_va": "0x341c",
    "file_offset": "0x341c",
    "raw_u32": "0x164a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a0"
  },
  "00013420": {
    "elf_va": "0x3420",
    "file_offset": "0x3420",
    "raw_u32": "0x241",
    "target_elf_va": "0x241"
  },
  "00013424": {
    "elf_va": "0x3424",
    "file_offset": "0x3424",
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
  "00013428": {
    "elf_va": "0x3428",
    "file_offset": "0x3428",
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
  "0001342c": {
    "elf_va": "0x342c",
    "file_offset": "0x342c",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00013430": {
    "elf_va": "0x3430",
    "file_offset": "0x3430",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00013434": {
    "elf_va": "0x3434",
    "file_offset": "0x3434",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91548,
      "symbol_defined": true
    },
    "target_elf_va": "0x1659c"
  },
  "00013438": {
    "elf_va": "0x3438",
    "file_offset": "0x3438",
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
  "0001343c": {
    "elf_va": "0x343c",
    "file_offset": "0x343c",
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
  "00013440": {
    "elf_va": "0x3440",
    "file_offset": "0x3440",
    "raw_u32": "0x4c00",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c00",
    "target_string": "[%s] BIOS SPI Feature is not enabled\n"
  },
  "00013444": {
    "elf_va": "0x3444",
    "file_offset": "0x3444",
    "raw_u32": "0x4c28",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c28",
    "target_string": "Error while active Host SPI driver"
  },
  "00013448": {
    "elf_va": "0x3448",
    "file_offset": "0x3448",
    "raw_u32": "0x4ccc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4ccc",
    "target_string": "\nFlash Image Size(%u)  is greater than Free Memory(%u) in RAM \n\n"
  },
  "0001344c": {
    "elf_va": "0x344c",
    "file_offset": "0x344c",
    "raw_u32": "0x4c4c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c4c",
    "target_string": "Error while finding the host boot SPI Device"
  },
  "00013450": {
    "elf_va": "0x3450",
    "file_offset": "0x3450",
    "raw_u32": "0x4c7c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4c7c",
    "target_string": "\nError in getting free RAM Memory using Sysinfo system call \n Error Code:%d\n"
  }
}
*/

undefined4
bios_prepare_comp(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  char *__name;
  int iVar6;
  int iStack_1007c;
  uint uStack_10078;
  sysinfo sStack_10074;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  uVar5 = DAT_00013428;
  uVar4 = DAT_00013424;
  uVar3 = DAT_00013420;
  puVar2 = DAT_0001341c;
  uVar1 = DAT_00013418;
  DAT_0001341c[2] = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x82,uVar5,uVar4,uVar3,uVar1);
  memset(auStack_10034,0,DAT_0001342c);
  memcpy(&iStack_1007c,(void *)((int)&uStack_8 + 2),4);
  memcpy(&uStack_10078,(void *)((int)&uStack_4 + 2),4);
  if (iStack_1007c == *DAT_00013430) {
    iVar6 = Check_FeatureList();
    if (iVar6 == 1) {
      iVar6 = ActiveHostSPIDriver(0);
      if (iVar6 == 0) {
        iVar6 = find_bios_spi_device(DAT_00013434);
        if (iVar6 == 0) {
          iVar6 = sysinfo(&sStack_10074);
          __name = DAT_00013438;
          if (iVar6 == 0) {
            if (sStack_10074.freeram < uStack_10078) {
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00013448);
              uStack_1002c = 0;
              iStack_10030 = 0xffffff;
            }
            else {
              puVar2[4] = uStack_10078;
              puVar2[3] = (uint)((uStack_10078 & 0xffffff) != 0);
              iVar6 = access(__name,0);
              if (iVar6 == 0) {
                unlink(DAT_00013438);
              }
              iVar6 = access(DAT_0001343c,0);
              if (iVar6 == 0) {
                unlink(DAT_0001343c);
              }
              *puVar2 = 0;
              puVar2[1] = 0;
              uStack_1002c = 0;
              if (iStack_10030 == 0) goto LAB_00013294;
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x86,DAT_00013450,iVar6);
            uStack_1002c = 0;
            iStack_10030 = 0xffffff;
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_0001344c);
          uStack_1002c = 0;
          iStack_10030 = 0xffffff;
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013444);
        uStack_1002c = 0;
        iStack_10030 = 0xffffff;
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013440,uVar1);
      uStack_1002c = 0;
      iStack_10030 = 6;
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_00013294:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

