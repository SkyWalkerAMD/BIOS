/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011d64": {
    "elf_va": "0x1d64",
    "file_offset": "0x1d64",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00011d68": {
    "elf_va": "0x1d68",
    "file_offset": "0x1d68",
    "raw_u32": "0x247c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x247c",
    "target_string": "$FID"
  },
  "00011d6c": {
    "elf_va": "0x1d6c",
    "file_offset": "0x1d6c",
    "raw_u32": "0x232",
    "target_elf_va": "0x232"
  },
  "00011d70": {
    "elf_va": "0x1d70",
    "file_offset": "0x1d70",
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
  "00011d74": {
    "elf_va": "0x1d74",
    "file_offset": "0x1d74",
    "raw_u32": "0x22d8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x22d8",
    "target_string": "[%s:%d]seek error on %s\n"
  },
  "00011d78": {
    "elf_va": "0x1d78",
    "file_offset": "0x1d78",
    "raw_u32": "0x22f4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x22f4",
    "target_string": "[%s:%d]Bytes read error %s\n"
  },
  "00011d7c": {
    "elf_va": "0x1d7c",
    "file_offset": "0x1d7c",
    "raw_u32": "0x1ea8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1ea8",
    "target_string": "/var/bios.bin"
  },
  "00011d80": {
    "elf_va": "0x1d80",
    "file_offset": "0x1d80",
    "raw_u32": "0x20d",
    "target_elf_va": "0x20d"
  },
  "00011d84": {
    "elf_va": "0x1d84",
    "file_offset": "0x1d84",
    "raw_u32": "0x22b4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x22b4",
    "target_string": "[%s:%d]Error while opening the file"
  },
  "00011d88": {
    "elf_va": "0x1d88",
    "file_offset": "0x1d88",
    "raw_u32": "0x2454",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2454",
    "target_string": "Invalid BIOS version check number (%d)\n"
  },
  "00011d8c": {
    "elf_va": "0x1d8c",
    "file_offset": "0x1d8c",
    "raw_u32": "0x215",
    "target_elf_va": "0x215"
  },
  "00011d90": {
    "elf_va": "0x1d90",
    "file_offset": "0x1d90",
    "raw_u32": "0x23d0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x23d0",
    "target_string": "[%s:%d]Failed in getting bios spi flash size \n"
  },
  "00011d94": {
    "elf_va": "0x1d94",
    "file_offset": "0x1d94",
    "raw_u32": "0x21a",
    "target_elf_va": "0x21a"
  },
  "00011d98": {
    "elf_va": "0x1d98",
    "file_offset": "0x1d98",
    "raw_u32": "0x2400",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2400",
    "target_string": "[%s:%d]Error while finding the host boot SPI Device"
  },
  "00011d9c": {
    "elf_va": "0x1d9c",
    "file_offset": "0x1d9c",
    "raw_u32": "0x221",
    "target_elf_va": "0x221"
  },
  "00011da0": {
    "elf_va": "0x1da0",
    "file_offset": "0x1da0",
    "raw_u32": "0x2434",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2434",
    "target_string": "[%s:%d]ERROR: open failed (%s)\n"
  },
  "00011da4": {
    "elf_va": "0x1da4",
    "file_offset": "0x1da4",
    "raw_u32": "0x206",
    "target_elf_va": "0x206"
  },
  "00011da8": {
    "elf_va": "0x1da8",
    "file_offset": "0x1da8",
    "raw_u32": "0x23a4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x23a4",
    "target_string": "[%s:%d]Failed in getting bios file size \n"
  }
}
*/

undefined4 GetBIOSFwVersion(int param_1,void *param_2)

{
  int iVar1;
  char *__s;
  int iVar2;
  __off_t _Var3;
  size_t sVar4;
  int iVar5;
  char *pcVar6;
  size_t sVar7;
  size_t __size;
  int iVar8;
  char *__s1;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  
  local_3c = 0;
  local_40 = 0;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  __size = *(size_t *)(DAT_00011d64 + 0x1c);
  if (param_1 == 1) {
    iVar1 = get_bios_file_size(&local_40);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011da8,DAT_00011d70,DAT_00011da4);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(DAT_00011d7c,2);
    if (iVar1 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d84,DAT_00011d70,DAT_00011d80);
      return 0xffffffff;
    }
  }
  else {
    if (param_1 != 2) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011d88,param_1);
      return 0xffffffff;
    }
    iVar1 = get_bios_spi_size(&local_40);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d90,DAT_00011d70,DAT_00011d8c);
      return 0xffffffff;
    }
    iVar1 = find_bios_spi_device(&local_3c);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d98,DAT_00011d70,DAT_00011d94);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(&local_3c,2);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011da0,DAT_00011d70,DAT_00011d9c,&local_3c);
      return 0xffffffff;
    }
  }
  __s = malloc(__size);
  iVar2 = FUN_00011dac(local_40,__size);
  pcVar6 = DAT_00011d68;
  __s1 = __s;
  if (0 < iVar2) {
    iVar2 = 0;
    iVar8 = 0;
    do {
      memset(__s,0,__size);
      _Var3 = lseek(iVar1,iVar2,0);
      if (_Var3 == -1) {
        pcVar6 = strerror(0);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d74,DAT_00011d70,DAT_00011d6c,pcVar6);
        goto LAB_00011c00;
      }
      sVar4 = sigwrap_read(iVar1,__s,__size);
      if (__size != sVar4) {
        pcVar6 = strerror(0);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d78,DAT_00011d70,0x238,pcVar6);
        goto LAB_00011c00;
      }
      if ((int)__size < 1) {
        sVar4 = 0;
      }
      else {
        sVar7 = 0;
        do {
          __s1 = __s + sVar7;
          iVar5 = strncmp(__s1,pcVar6,4);
          sVar7 = sVar7 + 1;
          if (iVar5 == 0) goto LAB_00011bf0;
          sVar4 = __size;
        } while (__size != sVar7);
      }
      iVar5 = FUN_00011dac(local_40,__size);
      iVar8 = iVar8 + 1;
      iVar2 = iVar2 + __size;
    } while (iVar8 < iVar5);
    __s1 = __s + sVar4;
  }
LAB_00011bf0:
  memcpy(param_2,__s1,0x80);
LAB_00011c00:
  free(__s);
  sigwrap_close(iVar1);
  return 0;
}

