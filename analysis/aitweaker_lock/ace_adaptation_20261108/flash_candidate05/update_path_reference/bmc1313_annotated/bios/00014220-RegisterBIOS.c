/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00014258": {
    "elf_va": "0x4258",
    "file_offset": "0x4258",
    "raw_u32": "0x555",
    "target_elf_va": "0x555"
  },
  "0001425c": {
    "elf_va": "0x425c",
    "file_offset": "0x425c",
    "raw_u32": "0x4488",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4488",
    "target_string": "compmngramibios.c"
  },
  "00014260": {
    "elf_va": "0x4260",
    "file_offset": "0x4260",
    "raw_u32": "0x5234",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5234",
    "target_string": "[%s:%d]COMP_MNGR : Registering the BIOS component"
  },
  "00014264": {
    "elf_va": "0x4264",
    "file_offset": "0x4264",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "Amibios_Command_Process",
      "symbol_va": 7800,
      "symbol_defined": true
    },
    "target_elf_va": "0x1e78",
    "target_function": "Amibios_Command_Process"
  },
  "00014268": {
    "elf_va": "0x4268",
    "file_offset": "0x4268",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "init_BIOS",
      "symbol_va": 9888,
      "symbol_defined": true
    },
    "target_elf_va": "0x26a0",
    "target_function": "init_BIOS"
  }
}
*/

void RegisterBIOS(int param_1)

{
  undefined4 uVar1;
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014260,DAT_0001425c,DAT_00014258);
  uVar1 = DAT_00014268;
  *(undefined4 *)(param_1 + 0x10c) = DAT_00014264;
  *(undefined4 *)(param_1 + 0x104) = uVar1;
  *(undefined4 *)(param_1 + 0x110) = 0;
  return;
}

