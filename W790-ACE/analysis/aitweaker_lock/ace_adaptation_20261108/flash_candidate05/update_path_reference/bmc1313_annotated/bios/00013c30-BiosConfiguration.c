/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013ccc": {
    "elf_va": "0x3ccc",
    "file_offset": "0x3ccc",
    "raw_u32": "0x44ac",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44ac",
    "target_string": "/usr/local/lib/libpdkapp.so"
  },
  "00013cd0": {
    "elf_va": "0x3cd0",
    "file_offset": "0x3cd0",
    "raw_u32": "0x5000",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5000",
    "target_string": "PDK_ASUSBIOSConfiguration"
  },
  "00013cd4": {
    "elf_va": "0x3cd4",
    "file_offset": "0x3cd4",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91548,
      "symbol_defined": true
    },
    "target_elf_va": "0x1659c"
  },
  "00013cd8": {
    "elf_va": "0x3cd8",
    "file_offset": "0x3cd8",
    "raw_u32": "0x4d10",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d10",
    "target_string": "/var/bios.bin"
  },
  "00013cdc": {
    "elf_va": "0x3cdc",
    "file_offset": "0x3cdc",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_ASUSBiosHeader",
      "symbol_va": 91332,
      "symbol_defined": true
    },
    "target_elf_va": "0x164c4"
  },
  "00013ce0": {
    "elf_va": "0x3ce0",
    "file_offset": "0x3ce0",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_mtdASUSBiosHeader",
      "symbol_va": 91568,
      "symbol_defined": true
    },
    "target_elf_va": "0x165b0"
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
  
  iVar1 = dlopen(DAT_00013ccc,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013cd0), pcVar2 == (code *)0x0)) {
    uVar5 = 0xffffffff;
  }
  else {
    uVar3 = sigwrap_open(DAT_00013cd4,2);
    uVar4 = sigwrap_open(DAT_00013cd8,2);
    uVar5 = (*pcVar2)(uVar3,uVar4,param_1,DAT_00013ce0,DAT_00013cdc);
    sigwrap_close(uVar3);
    sigwrap_close(uVar4);
  }
  dlclose(iVar1);
  return uVar5;
}

