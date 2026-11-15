/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011598": {
    "elf_va": "0x1598",
    "file_offset": "0x1598",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "0001159c": {
    "elf_va": "0x159c",
    "file_offset": "0x159c",
    "raw_u32": "0x213c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x213c",
    "target_string": "Skipping the erase block %d\n"
  },
  "000115a0": {
    "elf_va": "0x15a0",
    "file_offset": "0x15a0",
    "raw_u32": "0x105",
    "target_elf_va": "0x105"
  },
  "000115a4": {
    "elf_va": "0x15a4",
    "file_offset": "0x15a4",
    "raw_u32": "0x1eb8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1eb8",
    "target_string": "hosthelper.c"
  },
  "000115a8": {
    "elf_va": "0x15a8",
    "file_offset": "0x15a8",
    "raw_u32": "0x2110",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2110",
    "target_string": "[%s:%d]\n Reading failed from MTD to Buffer\n"
  },
  "000115ac": {
    "elf_va": "0x15ac",
    "file_offset": "0x15ac",
    "raw_u32": "0x215c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x215c",
    "target_string": "Flashing the erase block %d\n"
  },
  "000115b0": {
    "elf_va": "0x15b0",
    "file_offset": "0x15b0",
    "raw_u32": "0x40084d02",
    "target_elf_va": "0x40084d02"
  },
  "000115b4": {
    "elf_va": "0x15b4",
    "file_offset": "0x15b4",
    "raw_u32": "0x21c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x21c8",
    "target_string": "[%s:%d]\n Writing failed \n"
  },
  "000115b8": {
    "elf_va": "0x15b8",
    "file_offset": "0x15b8",
    "raw_u32": "0x20ac",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x20ac",
    "target_string": "[%s:%d]\n memory allocate for Buffer failed \n"
  },
  "000115bc": {
    "elf_va": "0x15bc",
    "file_offset": "0x15bc",
    "raw_u32": "0x20dc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x20dc",
    "target_string": "[%s:%d]\nSeeking failed for fd MTD_Device Offset %d\n"
  },
  "000115c0": {
    "elf_va": "0x15c0",
    "file_offset": "0x15c0",
    "raw_u32": "0x135",
    "target_elf_va": "0x135"
  },
  "000115c4": {
    "elf_va": "0x15c4",
    "file_offset": "0x15c4",
    "raw_u32": "0x21a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x21a0",
    "target_string": "[%s:%d]\n Seek failed before writing \n"
  },
  "000115c8": {
    "elf_va": "0x15c8",
    "file_offset": "0x15c8",
    "raw_u32": "0x12e",
    "target_elf_va": "0x12e"
  },
  "000115cc": {
    "elf_va": "0x15cc",
    "file_offset": "0x15cc",
    "raw_u32": "0x217c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x217c",
    "target_string": "[%s:%d]\n Memerase failed in ioctl \n"
  }
}
*/

undefined4 spi_write_erase_block(int param_1,char *param_2,__off_t param_3)

{
  int iVar1;
  char *__ptr;
  __off_t _Var2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  __off_t local_28;
  int local_24;
  
  iVar1 = DAT_00011598;
  __ptr = malloc(*(size_t *)(DAT_00011598 + 0x1c));
  if (__ptr == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000115b8,DAT_000115a4,0xf7);
    return 0xffffffff;
  }
  _Var2 = lseek(param_1,param_3,0);
  if (_Var2 == -1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000115bc,DAT_000115a4,0xff,param_3);
  }
  else {
    iVar3 = sigwrap_read(param_1,__ptr,*(undefined4 *)(iVar1 + 0x1c));
    iVar5 = *(int *)(iVar1 + 0x1c);
    if (iVar3 == iVar5) {
      if (iVar5 < 1) {
        if (iVar5 == 0) {
LAB_00011414:
          free(__ptr);
          uVar4 = FUN_00011dac(param_3,iVar3);
          IDBG_LINUXAPP_DbgOut(0x86,DAT_0001159c,uVar4);
          return 0;
        }
      }
      else if (*__ptr == *param_2) {
        iVar3 = 0;
        do {
          param_2 = param_2 + 1;
          __ptr = __ptr + 1;
          iVar3 = iVar3 + 1;
          if (iVar5 == iVar3) {
            __ptr = __ptr + -iVar5;
            iVar3 = iVar5;
            goto LAB_00011414;
          }
        } while (*__ptr == *param_2);
        param_2 = param_2 + -iVar3;
        __ptr = __ptr + -iVar3;
      }
      free(__ptr);
      local_28 = param_3;
      local_24 = iVar5;
      uVar4 = FUN_00011dac(param_3,iVar5);
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000115ac,uVar4);
      iVar3 = ioctl(param_1,DAT_000115b0,&local_28);
      if (iVar3 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000115cc,DAT_000115a4,DAT_000115c8);
        return 0xffffffff;
      }
      _Var2 = lseek(param_1,param_3,0);
      if (_Var2 != -1) {
        iVar3 = sigwrap_write(param_1,param_2,*(undefined4 *)(iVar1 + 0x1c));
        if (iVar3 != *(int *)(iVar1 + 0x1c)) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000115b4,DAT_000115a4,0x13c);
          return 0xffffffff;
        }
        return 0;
      }
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000115c4,DAT_000115a4,DAT_000115c0);
      return 0xffffffff;
    }
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000115a8,DAT_000115a4,DAT_000115a0);
  }
  free(__ptr);
  return 0xffffffff;
}

