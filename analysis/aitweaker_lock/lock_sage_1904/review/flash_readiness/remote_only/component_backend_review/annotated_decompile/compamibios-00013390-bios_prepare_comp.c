/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000135b4": {
    "elf_va": "0x35b4",
    "file_offset": "0x35b4",
    "raw_u32": "0x4294",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4294",
    "target_string": "bios_prepare_comp"
  },
  "DAT_or_PTR_000135b8": {
    "elf_va": "0x35b8",
    "file_offset": "0x35b8",
    "raw_u32": "0x16460",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16460"
  },
  "DAT_or_PTR_000135bc": {
    "elf_va": "0x35bc",
    "file_offset": "0x35bc",
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
  "DAT_or_PTR_000135c0": {
    "elf_va": "0x35c0",
    "file_offset": "0x35c0",
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
  "DAT_or_PTR_000135c4": {
    "elf_va": "0x35c4",
    "file_offset": "0x35c4",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_000135c8": {
    "elf_va": "0x35c8",
    "file_offset": "0x35c8",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_000135cc": {
    "elf_va": "0x35cc",
    "file_offset": "0x35cc",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1655c"
  },
  "DAT_or_PTR_000135d0": {
    "elf_va": "0x35d0",
    "file_offset": "0x35d0",
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
  "DAT_or_PTR_000135d4": {
    "elf_va": "0x35d4",
    "file_offset": "0x35d4",
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
  "DAT_or_PTR_000135d8": {
    "elf_va": "0x35d8",
    "file_offset": "0x35d8",
    "raw_u32": "0x4b04",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b04",
    "target_string": "[%s] BIOS SPI Feature is not enabled\n"
  },
  "DAT_or_PTR_000135dc": {
    "elf_va": "0x35dc",
    "file_offset": "0x35dc",
    "raw_u32": "0x4b2c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b2c",
    "target_string": "Error while active Host SPI driver"
  },
  "DAT_or_PTR_000135e0": {
    "elf_va": "0x35e0",
    "file_offset": "0x35e0",
    "raw_u32": "0x4bd0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4bd0",
    "target_string": "\nFlash Image Size(%u)  is greater than Free Memory(%u) in RAM \n\n"
  },
  "DAT_or_PTR_000135e4": {
    "elf_va": "0x35e4",
    "file_offset": "0x35e4",
    "raw_u32": "0x4b50",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b50",
    "target_string": "Error while finding the host boot SPI Device"
  },
  "DAT_or_PTR_000135e8": {
    "elf_va": "0x35e8",
    "file_offset": "0x35e8",
    "raw_u32": "0x4b80",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b80",
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
  char *__name;
  int iVar5;
  int iStack_1007c;
  uint uStack_10078;
  sysinfo sStack_10074;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  uVar4 = DAT_000135c0;
  uVar3 = DAT_000135bc;
  puVar2 = DAT_000135b8;
  uVar1 = DAT_000135b4;
  DAT_000135b8[2] = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x82,uVar4,uVar3,0x1ec,uVar1);
  memset(auStack_10034,0,DAT_000135c4);
  memcpy(&iStack_1007c,(void *)((int)&uStack_8 + 2),4);
  memcpy(&uStack_10078,(void *)((int)&uStack_4 + 2),4);
  if (iStack_1007c == *DAT_000135c8) {
    iVar5 = Check_FeatureList();
    if (iVar5 == 1) {
      iVar5 = ActiveHostSPIDriver(0);
      if (iVar5 == 0) {
        iVar5 = find_bios_spi_device(DAT_000135cc);
        if (iVar5 == 0) {
          iVar5 = sysinfo(&sStack_10074);
          __name = DAT_000135d0;
          if (iVar5 == 0) {
            if (sStack_10074.freeram < uStack_10078) {
              IDBG_LINUXAPP_DbgOut(0x86,DAT_000135e0);
              uStack_1002c = 0;
              iStack_10030 = 0xffffff;
            }
            else {
              puVar2[4] = uStack_10078;
              puVar2[3] = (uint)((uStack_10078 & 0xffffff) != 0);
              iVar5 = access(__name,0);
              if (iVar5 == 0) {
                unlink(DAT_000135d0);
              }
              iVar5 = access(DAT_000135d4,0);
              if (iVar5 == 0) {
                unlink(DAT_000135d4);
              }
              *puVar2 = 0;
              puVar2[1] = 0;
              uStack_1002c = 0;
              if (iStack_10030 == 0) goto LAB_00013430;
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x86,DAT_000135e8,iVar5);
            uStack_1002c = 0;
            iStack_10030 = 0xffffff;
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_000135e4);
          uStack_1002c = 0;
          iStack_10030 = 0xffffff;
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000135dc);
        uStack_1002c = 0;
        iStack_10030 = 0xffffff;
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000135d8,uVar1);
      uStack_1002c = 0;
      iStack_10030 = 6;
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_00013430:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

