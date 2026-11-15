/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013c24": {
    "elf_va": "0x3c24",
    "file_offset": "0x3c24",
    "raw_u32": "0x4354",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4354",
    "target_string": "/usr/local/lib/libpdkapp.so"
  },
  "DAT_or_PTR_00013c28": {
    "elf_va": "0x3c28",
    "file_offset": "0x3c28",
    "raw_u32": "0x4ddc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4ddc",
    "target_string": "PDK_ASUSBIOSConfiguration"
  },
  "DAT_or_PTR_00013c2c": {
    "elf_va": "0x3c2c",
    "file_offset": "0x3c2c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1655c"
  },
  "DAT_or_PTR_00013c30": {
    "elf_va": "0x3c30",
    "file_offset": "0x3c30",
    "raw_u32": "0x4938",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4938",
    "target_string": "/var/bios.bin"
  },
  "DAT_or_PTR_00013c34": {
    "elf_va": "0x3c34",
    "file_offset": "0x3c34",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_ASUSBiosHeader",
      "symbol_va": 91268,
      "symbol_defined": true
    },
    "target_elf_va": "0x16484"
  },
  "DAT_or_PTR_00013c38": {
    "elf_va": "0x3c38",
    "file_offset": "0x3c38",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_mtdASUSBiosHeader",
      "symbol_va": 91504,
      "symbol_defined": true
    },
    "target_elf_va": "0x16570"
  }
}
*/

undefined4 BiosConfiguration(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  iVar1 = dlopen(DAT_00013c24,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013c28), pcVar2 == (code *)0x0)) {
    uVar5 = 0xffffffff;
  }
  else {
    uVar3 = sigwrap_open(DAT_00013c2c,2);
    uVar4 = sigwrap_open(DAT_00013c30,2);
    uVar5 = (*pcVar2)(uVar3,uVar4,param_1,DAT_00013c38,DAT_00013c34);
    sigwrap_close(uVar3);
    sigwrap_close(uVar4);
  }
  dlclose(iVar1);
  return uVar5;
}

