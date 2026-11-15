/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000120a4": {
    "elf_va": "0x20a4",
    "file_offset": "0x20a4",
    "raw_u32": "0x3848",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3848",
    "target_string": "out"
  },
  "DAT_or_PTR_000120a8": {
    "elf_va": "0x20a8",
    "file_offset": "0x20a8",
    "raw_u32": "0x37dc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x37dc",
    "target_string": "/sys/class/gpio/gpio%d/direction"
  },
  "DAT_or_PTR_000120ac": {
    "elf_va": "0x20ac",
    "file_offset": "0x20ac",
    "raw_u32": "0x3828",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3828",
    "target_string": "/sys/class/gpio/gpio%d/value"
  },
  "DAT_or_PTR_000120b0": {
    "elf_va": "0x20b0",
    "file_offset": "0x20b0",
    "raw_u32": "0x34ac",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x34ac",
    "target_string": "PDK_SwitchBIOSFlash"
  },
  "DAT_or_PTR_000120b4": {
    "elf_va": "0x20b4",
    "file_offset": "0x20b4",
    "raw_u32": "0x3800",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x3800",
    "target_string": "[%s]Get GPIO_BIOS_FLASH_SWITCH failed\n"
  }
}
*/

undefined4 PDK_SwitchBIOSFlash(char param_1)

{
  int iVar1;
  undefined4 local_3c;
  char acStack_38 [40];
  
  memset(acStack_38,0,0x28);
  local_3c = *DAT_000120a4;
  snprintf(acStack_38,0x28,DAT_000120a8,0xf);
  iVar1 = sigwrap_open(acStack_38,2);
  if (-1 < iVar1) {
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    local_3c = 0;
    snprintf(acStack_38,0x28,DAT_000120ac,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (-1 < iVar1) {
      local_3c = CONCAT31(local_3c._1_3_,param_1 + '0');
      write(iVar1,&local_3c,1);
      sigwrap_close(iVar1);
      return 0;
    }
  }
  printf(DAT_000120b4,DAT_000120b0);
  return 0xffffffff;
}

