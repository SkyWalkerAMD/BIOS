/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011334": {
    "elf_va": "0x1334",
    "file_offset": "0x1334",
    "raw_u32": "0x1f1c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1f1c",
    "target_string": "/proc/mtd"
  },
  "00011338": {
    "elf_va": "0x1338",
    "file_offset": "0x1338",
    "raw_u32": "0x1ea4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1ea4",
    "target_string": "r"
  },
  "0001133c": {
    "elf_va": "0x133c",
    "file_offset": "0x133c",
    "raw_u32": "0x1f58",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1f58",
    "target_string": "Host SPI Flash"
  },
  "00011340": {
    "elf_va": "0x1340",
    "file_offset": "0x1340",
    "raw_u32": "0x2030",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2030",
    "target_string": ":"
  },
  "00011344": {
    "elf_va": "0x1344",
    "file_offset": "0x1344",
    "raw_u32": "0x20a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x20a0",
    "target_string": "/dev/mtd%d"
  },
  "00011348": {
    "elf_va": "0x1348",
    "file_offset": "0x1348",
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
  "0001134c": {
    "elf_va": "0x134c",
    "file_offset": "0x134c",
    "raw_u32": "0x2034",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2034",
    "target_string": "[%s:%d]Error in finding the BIOS Partition \n"
  },
  "00011350": {
    "elf_va": "0x1350",
    "file_offset": "0x1350",
    "raw_u32": "0x2064",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2064",
    "target_string": "[%s:%d]Unable to find HOST SPI / PNOR  MTD partition...\n"
  },
  "00011354": {
    "elf_va": "0x1354",
    "file_offset": "0x1354",
    "raw_u32": "0x1e8c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1e8c",
    "target_string": "find_bios_spi_device"
  },
  "00011358": {
    "elf_va": "0x1358",
    "file_offset": "0x1358",
    "raw_u32": "0x200c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x200c",
    "target_string": "[%s:%d]%s - Empty MTD_Device!!! \n"
  },
  "0001135c": {
    "elf_va": "0x135c",
    "file_offset": "0x135c",
    "raw_u32": "0x1f28",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1f28",
    "target_string": "[%s:%d]Unable to open %s to get MTD info...\n"
  }
}
*/

undefined4 find_bios_spi_device(char *param_1)

{
  char *__needle;
  char *__delim;
  FILE *__stream;
  char *pcVar1;
  size_t sVar2;
  long lVar3;
  undefined4 uVar4;
  char local_74 [88];
  
  pcVar1 = DAT_00011334;
  local_74[0] = '\0';
  local_74[1] = '\0';
  local_74[2] = '\0';
  local_74[3] = '\0';
  if (param_1 == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011358,DAT_00011348,0xbe,DAT_00011354);
    uVar4 = 0xffffffff;
  }
  else {
    __stream = fopen(DAT_00011334,DAT_00011338);
    __delim = DAT_00011340;
    __needle = DAT_0001133c;
    if (__stream == (FILE *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001135c,DAT_00011348,200,pcVar1);
      uVar4 = 0xffffffff;
    }
    else {
      lVar3 = -1;
      while (pcVar1 = fgets(local_74 + 4,0x50,__stream), pcVar1 != (char *)0x0) {
        pcVar1 = strstr(local_74 + 4,__needle);
        if (pcVar1 != (char *)0x0) {
          pcVar1 = strtok(local_74 + 4,__delim);
          if (pcVar1 == (char *)0x0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_0001134c,DAT_00011348,0xd3);
            fclose(__stream);
            return 0xffffffff;
          }
          sVar2 = strlen(pcVar1);
          memcpy(local_74,pcVar1 + 3,sVar2 - 3);
          lVar3 = strtol(local_74,(char **)0x0,10);
        }
      }
      fclose(__stream);
      if (lVar3 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011350,DAT_00011348,0xe0);
        uVar4 = 0xffffffff;
      }
      else {
        snprintf(param_1,0x14,DAT_00011344,lVar3);
        uVar4 = 0;
      }
    }
  }
  return uVar4;
}

