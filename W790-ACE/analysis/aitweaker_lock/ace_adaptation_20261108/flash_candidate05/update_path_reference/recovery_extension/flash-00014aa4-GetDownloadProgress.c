/* Exact ELF literal map, Ghidra bias0x10000. */
{
  "00014d4c": {
    "elf_va": "0x4d4c",
    "file_offset": "0x4d4c",
    "raw_u32": "0x91ec",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x91ec",
    "target_string": "flashlib.c"
  },
  "00014d50": {
    "elf_va": "0x4d50",
    "file_offset": "0x4d50",
    "raw_u32": "0x99bc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x99bc",
    "target_string": "[%s:%d]in get download prog\n"
  },
  "00014d54": {
    "elf_va": "0x4d54",
    "file_offset": "0x4d54",
    "raw_u32": "0x9410",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x9410",
    "target_string": "r"
  },
  "00014d58": {
    "elf_va": "0x4d58",
    "file_offset": "0x4d58",
    "raw_u32": "0x9890",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x9890",
    "target_string": "/var/flasher.progress"
  },
  "00014d5c": {
    "elf_va": "0x4d5c",
    "file_offset": "0x4d5c",
    "raw_u32": "0x478",
    "target_elf_va": "0x478"
  },
  "00014d60": {
    "elf_va": "0x4d60",
    "file_offset": "0x4d60",
    "raw_u32": "0x48d",
    "target_elf_va": "0x48d"
  },
  "00014d64": {
    "elf_va": "0x4d64",
    "file_offset": "0x4d64",
    "raw_u32": "0x99dc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x99dc",
    "target_string": "[%s:%d]End of file reached while reading download progress\n"
  },
  "00014d68": {
    "elf_va": "0x4d68",
    "file_offset": "0x4d68",
    "raw_u32": "0x992c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x992c",
    "target_string": "retrying reading status file..."
  },
  "00014d6c": {
    "elf_va": "0x4d6c",
    "file_offset": "0x4d6c",
    "raw_u32": "0x4b9",
    "target_elf_va": "0x4b9"
  },
  "00014d70": {
    "elf_va": "0x4d70",
    "file_offset": "0x4d70",
    "raw_u32": "0x997c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x997c",
    "target_string": "[%s:%d]Read prpgress file in flashlib\n"
  },
  "00014d74": {
    "elf_va": "0x4d74",
    "file_offset": "0x4d74",
    "raw_u32": "0x485",
    "target_elf_va": "0x485"
  },
  "00014d78": {
    "elf_va": "0x4d78",
    "file_offset": "0x4d78",
    "raw_u32": "0x98d0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x98d0",
    "target_string": "[%s:%d]Could not obtain lock\n"
  },
  "00014d7c": {
    "elf_va": "0x4d7c",
    "file_offset": "0x4d7c",
    "raw_u32": "0x9a48",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x9a48",
    "target_string": "Download Firmware Image Complete!!"
  },
  "00014d80": {
    "elf_va": "0x4d80",
    "file_offset": "0x4d80",
    "raw_u32": "0x49a",
    "target_elf_va": "0x49a"
  },
  "00014d84": {
    "elf_va": "0x4d84",
    "file_offset": "0x4d84",
    "raw_u32": "0x9a18",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x9a18",
    "target_string": "[%s:%d]Error while reading download progress!!\n"
  },
  "00014d88": {
    "elf_va": "0x4d88",
    "file_offset": "0x4d88",
    "raw_u32": "0x47e",
    "target_elf_va": "0x47e"
  },
  "00014d8c": {
    "elf_va": "0x4d8c",
    "file_offset": "0x4d8c",
    "raw_u32": "0x98a8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x98a8",
    "target_string": "[%s:%d]Error opening progress file: %s"
  }
}

undefined4 GetDownloadProgress(char *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char *__filename;
  FILE *__stream;
  int iVar3;
  size_t sVar4;
  int iVar5;
  int *piVar6;
  char *pcVar7;
  int iVar8;
  char local_8c;
  char local_8b;
  char acStack_89 [60];
  char acStack_4d [33];
  char local_2c;
  
  __filename = DAT_00014d58;
  pcVar7 = DAT_00014d54;
  uVar2 = DAT_00014d50;
  uVar1 = DAT_00014d4c;
  iVar8 = 3;
  do {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar2,uVar1,DAT_00014d5c);
    __stream = fopen(__filename,pcVar7);
    if (__stream == (FILE *)0x0) {
      piVar6 = __errno_location();
      pcVar7 = strerror(*piVar6);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d8c,DAT_00014d4c,DAT_00014d88,pcVar7);
      return 5;
    }
    memset(&local_8c,0,0x61);
    fileno(__stream);
    iVar3 = file_lock_read();
    if (iVar3 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d78,uVar1,DAT_00014d74);
    }
    sVar4 = fread(&local_8c,0x61,1,__stream);
    if (sVar4 == 1) {
      if (iVar3 == 0) {
        fileno(__stream);
        file_unlock();
      }
      fclose(__stream);
      break;
    }
    iVar5 = feof(__stream);
    if (iVar5 == 0) {
      iVar8 = ferror(__stream);
      if (iVar8 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d84,DAT_00014d4c,DAT_00014d80);
      }
      if (iVar3 == 0) {
        fileno(__stream);
        file_unlock();
      }
      fclose(__stream);
      return 5;
    }
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00014d64,uVar1,DAT_00014d60);
    if (iVar3 == 0) {
      fileno(__stream);
      file_unlock();
    }
    fclose(__stream);
    puts(DAT_00014d68);
    sleep(1);
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  if ((local_8c == '\x02') || (local_8b == '\x04')) {
    strncpy(param_1,acStack_89,0x3c);
    param_1[0x3b] = '\0';
    strncpy(param_1 + 0x3c,acStack_4d,0x1e);
    param_1[0x59] = '\0';
    param_1[0x5a] = SUB41(acStack_4d._29_4_,1);
    param_1[0x5b] = SUB41(acStack_4d._29_4_,2);
    param_1[0x5c] = SUB41(acStack_4d._29_4_,3);
    param_1[0x5d] = local_2c;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014d70,DAT_00014d4c,DAT_00014d6c);
  if ((local_8c == '\x02') && (*(int *)(param_1 + 0x5a) == 2)) {
    puts(DAT_00014d7c);
    if (*(int *)(param_1 + 0x5a) != 4) {
      return 0xff;
    }
  }
  else if (*(int *)(param_1 + 0x5a) != 4) {
    return 0;
  }
  return 0xfe;
}

