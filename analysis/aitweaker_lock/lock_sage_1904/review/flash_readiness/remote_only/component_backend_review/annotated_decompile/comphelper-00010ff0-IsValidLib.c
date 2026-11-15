/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00011034": {
    "elf_va": "0x1034",
    "file_offset": "0x1034",
    "raw_u32": "0x15dc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x15dc",
    "target_string": "."
  },
  "DAT_or_PTR_00011038": {
    "elf_va": "0x1038",
    "file_offset": "0x1038",
    "raw_u32": "0x15e0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x15e0",
    "target_string": ".."
  },
  "DAT_or_PTR_0001103c": {
    "elf_va": "0x103c",
    "file_offset": "0x103c",
    "raw_u32": "0x15e4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x15e4",
    "target_string": ".so"
  }
}
*/

bool IsValidLib(char *param_1)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = strcmp(param_1,DAT_00011034);
  if (iVar1 == 0) {
    return false;
  }
  iVar1 = strcmp(param_1,DAT_00011038);
  if (iVar1 == 0) {
    return false;
  }
  pcVar2 = strstr(param_1,DAT_0001103c);
  return pcVar2 != (char *)0x0;
}

