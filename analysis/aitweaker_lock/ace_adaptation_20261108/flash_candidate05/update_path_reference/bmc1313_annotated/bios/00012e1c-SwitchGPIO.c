/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012ea8": {
    "elf_va": "0x2ea8",
    "file_offset": "0x2ea8",
    "raw_u32": "0x43e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43e8",
    "target_string": "SwitchGPIO"
  },
  "00012eac": {
    "elf_va": "0x2eac",
    "file_offset": "0x2eac",
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
  "00012eb0": {
    "elf_va": "0x2eb0",
    "file_offset": "0x2eb0",
    "raw_u32": "0x4a3c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a3c",
    "target_string": "[%s:%d][%s] value = %d\n"
  },
  "00012eb4": {
    "elf_va": "0x2eb4",
    "file_offset": "0x2eb4",
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
  "00012eb8": {
    "elf_va": "0x2eb8",
    "file_offset": "0x2eb8",
    "raw_u32": "0x4a54",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a54",
    "target_string": "PDK_SwitchBIOSFlash"
  },
  "00012ebc": {
    "elf_va": "0x2ebc",
    "file_offset": "0x2ebc",
    "raw_u32": "0x4a68",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a68",
    "target_string": "Unable to Switch Bios Flash..."
  }
}
*/

int SwitchGPIO(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00012eb0,DAT_00012eac,0xbb,DAT_00012ea8,param_1);
  iVar1 = dlopen(DAT_00012eb4,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00012eb8), pcVar2 == (code *)0x0)) {
    iVar4 = -1;
  }
  else {
    iVar3 = (*pcVar2)(param_1);
    iVar4 = 0;
    if (iVar3 != 0) {
      dlclose(iVar1);
      puts(DAT_00012ebc);
      return iVar3;
    }
  }
  dlclose(iVar1);
  return iVar4;
}

