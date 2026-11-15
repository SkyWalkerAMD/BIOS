/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00010f90": {
    "elf_va": "0xf90",
    "file_offset": "0xf90",
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
  "00010f94": {
    "elf_va": "0xf94",
    "file_offset": "0xf94",
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
  "00010f98": {
    "elf_va": "0xf98",
    "file_offset": "0xf98",
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
  "00010f9c": {
    "elf_va": "0xf9c",
    "file_offset": "0xf9c",
    "raw_u32": "0x1ef0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1ef0",
    "target_string": "[%s:%d]Failed in updating bios file size \n"
  },
  "00010fa0": {
    "elf_va": "0xfa0",
    "file_offset": "0xfa0",
    "raw_u32": "0x1ec8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1ec8",
    "target_string": "[%s:%d]Error in opening the file : %s \n"
  }
}
*/

undefined4 get_bios_file_size(long *param_1)

{
  char *pcVar1;
  FILE *__stream;
  int iVar2;
  long lVar3;
  undefined4 uVar4;
  
  pcVar1 = DAT_00010f90;
  __stream = fopen(DAT_00010f90,DAT_00010f94);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00010fa0,DAT_00010f98,0x2b,pcVar1);
    uVar4 = 0xffffffff;
  }
  else {
    iVar2 = fseek(__stream,0,2);
    if (iVar2 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00010f9c,DAT_00010f98,0x31);
      fclose(__stream);
      uVar4 = 0xffffffff;
    }
    else {
      lVar3 = ftell(__stream);
      *param_1 = lVar3;
      iVar2 = fseek(__stream,0,0);
      if (iVar2 == -1) {
        fclose(__stream);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00010f9c,DAT_00010f98,0x3a);
        uVar4 = 0xffffffff;
      }
      else {
        fclose(__stream);
        uVar4 = 0;
      }
    }
  }
  return uVar4;
}

