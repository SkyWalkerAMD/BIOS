/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000142c4": {
    "elf_va": "0x42c4",
    "file_offset": "0x42c4",
    "raw_u32": "0x5934",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5934",
    "target_string": "ab"
  },
  "DAT_or_PTR_000142c8": {
    "elf_va": "0x42c8",
    "file_offset": "0x42c8",
    "raw_u32": "0x4ef",
    "target_elf_va": "0x4ef"
  },
  "DAT_or_PTR_000142cc": {
    "elf_va": "0x42cc",
    "file_offset": "0x42cc",
    "raw_u32": "0x51c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x51c0",
    "target_string": "compmngrhelper.c"
  },
  "DAT_or_PTR_000142d0": {
    "elf_va": "0x42d0",
    "file_offset": "0x42d0",
    "raw_u32": "0x5984",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5984",
    "target_string": "[%s:%d]Error while writing the data"
  },
  "DAT_or_PTR_000142d4": {
    "elf_va": "0x42d4",
    "file_offset": "0x42d4",
    "raw_u32": "0x4e8",
    "target_elf_va": "0x4e8"
  },
  "DAT_or_PTR_000142d8": {
    "elf_va": "0x42d8",
    "file_offset": "0x42d8",
    "raw_u32": "0x5958",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5958",
    "target_string": "[%s:%d]Error while seeking the offset %d"
  },
  "DAT_or_PTR_000142dc": {
    "elf_va": "0x42dc",
    "file_offset": "0x42dc",
    "raw_u32": "0x4e2",
    "target_elf_va": "0x4e2"
  },
  "DAT_or_PTR_000142e0": {
    "elf_va": "0x42e0",
    "file_offset": "0x42e0",
    "raw_u32": "0x5938",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5938",
    "target_string": "[%s:%d]Error while opening %s"
  }
}
*/

undefined4 file_write_data(char *param_1,void *param_2,long param_3,size_t param_4)

{
  FILE *__stream;
  int iVar1;
  size_t sVar2;
  undefined4 uVar3;
  
  __stream = fopen(param_1,DAT_000142c4);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000142e0,DAT_000142cc,DAT_000142dc,param_1);
    uVar3 = 0xffffffff;
  }
  else {
    iVar1 = fseek(__stream,param_3,0);
    if (iVar1 == 0) {
      sVar2 = fwrite(param_2,1,param_4,__stream);
      if (sVar2 == param_4) {
        fclose(__stream);
        uVar3 = 0;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000142d0,DAT_000142cc,DAT_000142c8);
        fclose(__stream);
        uVar3 = 0xffffffff;
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000142d8,DAT_000142cc,DAT_000142d4,param_3);
      fclose(__stream);
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}

