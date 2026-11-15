/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011bc8": {
    "elf_va": "0x1bc8",
    "file_offset": "0x1bc8",
    "raw_u32": "0x3e0c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3e0c",
    "target_string": "core_features"
  },
  "00011bcc": {
    "elf_va": "0x1bcc",
    "file_offset": "0x1bcc",
    "raw_u32": "0x19088",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x19088"
  },
  "00011bd0": {
    "elf_va": "0x1bd0",
    "file_offset": "0x1bd0",
    "raw_u32": "0x3f94",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f94",
    "target_string": "%s:%s"
  },
  "00011bd4": {
    "elf_va": "0x1bd4",
    "file_offset": "0x1bd4",
    "raw_u32": "0x3fb4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3fb4",
    "target_string": "0"
  },
  "00011bd8": {
    "elf_va": "0x1bd8",
    "file_offset": "0x1bd8",
    "raw_u32": "0x2ba",
    "target_elf_va": "0x2ba"
  },
  "00011bdc": {
    "elf_va": "0x1bdc",
    "file_offset": "0x1bdc",
    "raw_u32": "0x3f40",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f40",
    "target_string": "featuredef.c"
  },
  "00011be0": {
    "elf_va": "0x1be0",
    "file_offset": "0x1be0",
    "raw_u32": "0x3f9c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f9c",
    "target_string": "[%s:%d]Buffer overflow\n"
  },
  "00011be4": {
    "elf_va": "0x1be4",
    "file_offset": "0x1be4",
    "raw_u32": "0x3f0c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f0c",
    "target_string": "/var/tmp/libfeature"
  },
  "00011be8": {
    "elf_va": "0x1be8",
    "file_offset": "0x1be8",
    "raw_u32": "0x3f20",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f20",
    "target_string": "r"
  },
  "00011bec": {
    "elf_va": "0x1bec",
    "file_offset": "0x1bec",
    "raw_u32": "0x3f24",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f24",
    "target_string": "/etc/core_features"
  },
  "00011bf0": {
    "elf_va": "0x1bf0",
    "file_offset": "0x1bf0",
    "raw_u32": "0x3f38",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f38",
    "target_string": "%256s"
  },
  "00011bf4": {
    "elf_va": "0x1bf4",
    "file_offset": "0x1bf4",
    "raw_u32": "0x3f50",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f50",
    "target_string": "[%s:%d]Features::%s\n"
  },
  "00011bf8": {
    "elf_va": "0x1bf8",
    "file_offset": "0x1bf8",
    "raw_u32": "0x3f68",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f68",
    "target_string": "1"
  },
  "00011bfc": {
    "elf_va": "0x1bfc",
    "file_offset": "0x1bfc",
    "raw_u32": "0x3f6c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3f6c",
    "target_string": "No Project specific features available\n"
  }
}
*/

bool IsFeatureEnabled(undefined4 param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  char *pcVar6;
  size_t __n;
  FILE *__stream;
  char *pcVar7;
  undefined4 local_42c;
  char local_428 [256];
  undefined4 local_328;
  undefined4 uStack_324;
  undefined4 uStack_320;
  undefined2 local_31c;
  undefined1 auStack_31a [241];
  char cStack_229;
  char local_228 [255];
  char cStack_129;
  char local_128 [260];
  
  piVar1 = DAT_00011bcc;
  local_328 = *DAT_00011bc8;
  uStack_324 = DAT_00011bc8[1];
  uStack_320 = DAT_00011bc8[2];
  local_31c = (undefined2)DAT_00011bc8[3];
  memset(auStack_31a,0,0xf2);
  if (*piVar1 == 0) {
    iVar5 = IniLoadFile(DAT_00011be4);
    *piVar1 = iVar5;
    if (iVar5 == 0) {
      return false;
    }
    __stream = fopen(DAT_00011bec,DAT_00011be8);
    uVar4 = DAT_00011bf4;
    uVar3 = DAT_00011bf0;
    uVar2 = DAT_00011bdc;
    if (__stream == (FILE *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bfc);
      return false;
    }
    while (iVar5 = feof(__stream), iVar5 == 0) {
      memset(local_428,0,0x100);
      __isoc99_fscanf(__stream,uVar3,local_428);
      if (local_428[0] != '\0' && local_428[0] != '#') {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar4,uVar2,0x294,local_428);
        local_42c = strchr(local_428,0x3d);
        if (local_42c == (char *)0x0) {
          iniparser_add_entry(*piVar1,&local_328,local_428,DAT_00011bf8);
        }
        else {
          memset(local_228,0,0x100);
          memset(local_128,0,0x100);
          pcVar6 = &cStack_229;
          pcVar7 = (char *)((int)&local_42c + 3);
          do {
            pcVar7 = pcVar7 + 1;
            if (*pcVar7 == '=') break;
            pcVar6 = pcVar6 + 1;
            *pcVar6 = *pcVar7;
          } while (pcVar7 != local_428 + 0xff);
          pcVar7 = &cStack_129;
          pcVar6 = local_42c;
          do {
            pcVar6 = pcVar6 + 1;
            if (*pcVar6 == '\0') break;
            pcVar7 = pcVar7 + 1;
            *pcVar7 = *pcVar6;
          } while (pcVar6 != local_42c + 0xff);
          iniparser_add_entry(*piVar1,&local_328,local_228,local_128);
        }
      }
    }
    fclose(__stream);
  }
  memset(local_428,0,0x100);
  iVar5 = snprintf(local_428,0x100,DAT_00011bd0,DAT_00011bc8,param_1);
  if (iVar5 < 0x100) {
    pcVar6 = (char *)iniparser_getstring(*piVar1,local_428,DAT_00011bd4);
    __n = strlen(pcVar6);
    iVar5 = strncmp(pcVar6,DAT_00011bd4,__n);
    return iVar5 != 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00011be0,DAT_00011bdc,DAT_00011bd8);
  return false;
}

