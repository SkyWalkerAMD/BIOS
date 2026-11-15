/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00011758": {
    "elf_va": "0x1758",
    "file_offset": "0x1758",
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
  "0001175c": {
    "elf_va": "0x175c",
    "file_offset": "0x175c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00011760": {
    "elf_va": "0x1760",
    "file_offset": "0x1760",
    "raw_u32": "0x17a",
    "target_elf_va": "0x17a"
  },
  "00011764": {
    "elf_va": "0x1764",
    "file_offset": "0x1764",
    "raw_u32": "0x2298",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2298",
    "target_string": "[%s:%d]Flashing progress %d"
  },
  "00011768": {
    "elf_va": "0x1768",
    "file_offset": "0x1768",
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
  "0001176c": {
    "elf_va": "0x176c",
    "file_offset": "0x176c",
    "raw_u32": "0x16d",
    "target_elf_va": "0x16d"
  },
  "00011770": {
    "elf_va": "0x1770",
    "file_offset": "0x1770",
    "raw_u32": "0x222c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x222c",
    "target_string": "[%s:%d]Error while reading the data from BIOS Recovery file"
  },
  "00011774": {
    "elf_va": "0x1774",
    "file_offset": "0x1774",
    "raw_u32": "0x2268",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2268",
    "target_string": "[%s:%d]Error while writing the BIOS SPI Device"
  },
  "00011778": {
    "elf_va": "0x1778",
    "file_offset": "0x1778",
    "raw_u32": "0x155",
    "target_elf_va": "0x155"
  },
  "0001177c": {
    "elf_va": "0x177c",
    "file_offset": "0x177c",
    "raw_u32": "0x21e4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x21e4",
    "target_string": "[%s:%d]Error while opening %s"
  },
  "00011780": {
    "elf_va": "0x1780",
    "file_offset": "0x1780",
    "raw_u32": "0x15d",
    "target_elf_va": "0x15d"
  },
  "00011784": {
    "elf_va": "0x1784",
    "file_offset": "0x1784",
    "raw_u32": "0x2204",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x2204",
    "target_string": "[%s:%d]Error in allocating the memory"
  }
}
*/

undefined4
flash_bios_image(undefined4 param_1,char *param_2,int param_3,uint param_4,undefined4 *param_5)

{
  int iVar1;
  int iVar2;
  FILE *__stream;
  void *__ptr;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  size_t sVar6;
  size_t __size;
  undefined4 uVar7;
  uint uVar8;
  
  __stream = fopen(param_2,DAT_00011758);
  iVar2 = DAT_0001175c;
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001177c,DAT_00011768,DAT_00011778,param_2);
    uVar7 = 0xffffffff;
  }
  else {
    __size = *(size_t *)(DAT_0001175c + 0x1c);
    __ptr = malloc(__size);
    if (__ptr == (void *)0x0) {
      fclose(__stream);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011784,DAT_00011768,DAT_00011780);
      uVar7 = 0xffffffff;
    }
    else {
      if (__size <= param_4) {
        uVar8 = 0;
        do {
          sVar6 = fread(__ptr,1,__size,__stream);
          if (sVar6 != __size) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011770,DAT_00011768,DAT_0001176c);
            uVar7 = 0xffffffff;
            goto LAB_000116d4;
          }
          iVar3 = spi_write_erase_block(param_1,__ptr,param_3);
          iVar1 = uVar8 * 100;
          uVar8 = uVar8 + 1;
          if (iVar3 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011774,DAT_00011768,0x174);
            uVar7 = 0xffffffff;
            goto LAB_000116d4;
          }
          uVar7 = FUN_00011dac(param_4,*(undefined4 *)(iVar2 + 0x1c));
          uVar4 = FUN_00011dac(iVar1,uVar7);
          uVar7 = DAT_00011760;
          *param_5 = uVar4;
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011764,DAT_00011768,uVar7,uVar4);
          __size = *(size_t *)(iVar2 + 0x1c);
          uVar5 = FUN_00011dac(param_4,__size);
          param_3 = param_3 + __size;
        } while (uVar8 < uVar5);
      }
      uVar7 = 0;
LAB_000116d4:
      free(__ptr);
      fclose(__stream);
    }
  }
  return uVar7;
}

