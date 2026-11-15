/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011094": {
    "elf_va": "0x1094",
    "file_offset": "0x1094",
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
  "00011098": {
    "elf_va": "0x1098",
    "file_offset": "0x1098",
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
  "0001109c": {
    "elf_va": "0x109c",
    "file_offset": "0x109c",
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
  "000110a0": {
    "elf_va": "0x10a0",
    "file_offset": "0x10a0",
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
  "000110a4": {
    "elf_va": "0x10a4",
    "file_offset": "0x10a4",
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

undefined4 get_bios_spi_size(int *param_1)

{
  char *__needle;
  FILE *__stream;
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  char cStack_68;
  byte abStack_67 [79];
  
  pcVar1 = DAT_00011094;
  memset(&cStack_68,0,0x50);
  __stream = fopen(pcVar1,DAT_00011098);
  __needle = DAT_0001109c;
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000110a4,DAT_000110a0,0x4c,pcVar1);
    uVar3 = 0xffffffff;
  }
  else {
    iVar6 = 1;
    while (pcVar1 = fgets(&cStack_68,0x50,__stream), pcVar1 != (char *)0x0) {
      pcVar1 = strstr(&cStack_68,__needle);
      if (pcVar1 != (char *)0x0) {
        iVar2 = *param_1;
        if (abStack_67[3] == ':') {
          iVar7 = 0xd;
        }
        else {
          iVar7 = 0xe;
        }
        pbVar4 = abStack_67 + iVar7;
        do {
          pbVar4 = pbVar4 + -1;
          iVar5 = *pbVar4 - 0x30;
          if (9 < iVar5) {
            iVar5 = *pbVar4 - 0x57;
          }
          iVar2 = iVar6 * iVar5 + iVar2;
          iVar6 = iVar6 << 4;
        } while (pbVar4 != abStack_67 + iVar7 + -8);
        *param_1 = iVar2;
      }
    }
    fclose(__stream);
    uVar3 = 0;
  }
  return uVar3;
}

