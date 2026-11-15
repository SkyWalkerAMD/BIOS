/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013038": {
    "elf_va": "0x3038",
    "file_offset": "0x3038",
    "raw_u32": "0x4410",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4410",
    "target_string": "r"
  },
  "0001303c": {
    "elf_va": "0x303c",
    "file_offset": "0x303c",
    "raw_u32": "0x4998",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4998",
    "target_string": "ERROR: Can't open %s file.\n"
  },
  "00013040": {
    "elf_va": "0x3040",
    "file_offset": "0x3040",
    "raw_u32": "0x49b4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x49b4",
    "target_string": "ERROR: Can't read %s file.\n"
  }
}
*/

undefined4 read_file(char *param_1,undefined4 *param_2,size_t *param_3)

{
  FILE *__stream;
  size_t __size;
  void *__ptr;
  size_t sVar1;
  
  __stream = fopen(param_1,DAT_00013038);
  if (__stream == (FILE *)0x0) {
    printf(DAT_0001303c,param_1);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fseek(__stream,0,2);
  __size = ftell(__stream);
  rewind(__stream);
  __ptr = malloc(__size);
  *param_2 = __ptr;
  sVar1 = fread(__ptr,1,__size,__stream);
  if (sVar1 == __size) {
    *param_3 = sVar1;
    fclose(__stream);
    return 0;
  }
  printf(DAT_00013040,param_1);
                    /* WARNING: Subroutine does not return */
  exit(1);
}

