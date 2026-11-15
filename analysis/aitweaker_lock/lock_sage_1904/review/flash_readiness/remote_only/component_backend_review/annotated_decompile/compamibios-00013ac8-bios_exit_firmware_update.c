/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013b44": {
    "elf_va": "0x3b44",
    "file_offset": "0x3b44",
    "raw_u32": "0x42c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x42c8",
    "target_string": "bios_exit_firmware_update"
  },
  "DAT_or_PTR_00013b48": {
    "elf_va": "0x3b48",
    "file_offset": "0x3b48",
    "raw_u32": "0x4330",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4330",
    "target_string": "compmngramibios.c"
  },
  "DAT_or_PTR_00013b4c": {
    "elf_va": "0x3b4c",
    "file_offset": "0x3b4c",
    "raw_u32": "0x4344",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4344",
    "target_string": "[%s:%d][%s]\n"
  },
  "DAT_or_PTR_00013b50": {
    "elf_va": "0x3b50",
    "file_offset": "0x3b50",
    "raw_u32": "0x504",
    "target_elf_va": "0x504"
  }
}
*/

undefined4 bios_exit_firmware_update(void)

{
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013b4c,DAT_00013b48,DAT_00013b50,DAT_00013b44);
  ActiveHostSPIDriver(1);
  send_compmngr_response();
  return 0;
}

