/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "0001779c": {
    "elf_va": "0x779c",
    "file_offset": "0x779c",
    "raw_u32": "0xdeadbeef",
    "target_elf_va": "0xdeadbeef"
  },
  "000177a0": {
    "elf_va": "0x77a0",
    "file_offset": "0x77a0",
    "raw_u32": "0xb7a",
    "target_elf_va": "0xb7a"
  },
  "000177a4": {
    "elf_va": "0x77a4",
    "file_offset": "0x77a4",
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
  "000177a8": {
    "elf_va": "0x77a8",
    "file_offset": "0x77a8",
    "raw_u32": "0xac28",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xac28",
    "target_string": "[%s:%d]Error while reading magic sequence"
  },
  "000177ac": {
    "elf_va": "0x77ac",
    "file_offset": "0x77ac",
    "raw_u32": "0xb6b",
    "target_elf_va": "0xb6b"
  },
  "000177b0": {
    "elf_va": "0x77b0",
    "file_offset": "0x77b0",
    "raw_u32": "0xabd8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xabd8",
    "target_string": "[%s:%d]unable to open the file"
  },
  "000177b4": {
    "elf_va": "0x77b4",
    "file_offset": "0x77b4",
    "raw_u32": "0xb73",
    "target_elf_va": "0xb73"
  },
  "000177b8": {
    "elf_va": "0x77b8",
    "file_offset": "0x77b8",
    "raw_u32": "0xabf8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xabf8",
    "target_string": "[%s:%d]Error in while getting magic sequence"
  },
  "000177bc": {
    "elf_va": "0x77bc",
    "file_offset": "0x77bc",
    "raw_u32": "0xac54",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0xac54",
    "target_string": "hash length = %d %d %d\n"
  }
}
*/

int GetHashLength(int param_1)

{
  int __fd;
  __off_t _Var1;
  int iVar2;
  int local_18;
  uint local_14;
  
  if (param_1 == 0) {
    iVar2 = -1;
  }
  else {
    __fd = sigwrap_open(param_1,0);
    if (__fd == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000177b0,DAT_000177a4,DAT_000177ac);
      return -1;
    }
    _Var1 = lseek(__fd,-8,2);
    if (_Var1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000177b8,DAT_000177a4,DAT_000177b4);
      iVar2 = -1;
    }
    else {
      iVar2 = sigwrap_read(__fd,&local_18,8);
      if (iVar2 == 8) {
        iVar2 = 8;
        if (local_18 == DAT_0001779c) {
          iVar2 = ~(local_14 | 0xff000000) + 8;
          printf(DAT_000177bc,iVar2,~(local_14 | 0xff000000),8);
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000177a8,DAT_000177a4,DAT_000177a0);
        iVar2 = -1;
      }
    }
    sigwrap_close(__fd);
  }
  return iVar2;
}

