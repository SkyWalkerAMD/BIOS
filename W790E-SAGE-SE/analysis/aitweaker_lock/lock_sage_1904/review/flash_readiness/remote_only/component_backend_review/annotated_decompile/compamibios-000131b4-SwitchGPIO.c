/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013240": {
    "elf_va": "0x3240",
    "file_offset": "0x3240",
    "raw_u32": "0x4274",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4274",
    "target_string": "SwitchGPIO"
  },
  "DAT_or_PTR_00013244": {
    "elf_va": "0x3244",
    "file_offset": "0x3244",
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
  "DAT_or_PTR_00013248": {
    "elf_va": "0x3248",
    "file_offset": "0x3248",
    "raw_u32": "0x4a20",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a20",
    "target_string": "[%s:%d][%s] value = %d\n"
  },
  "DAT_or_PTR_0001324c": {
    "elf_va": "0x324c",
    "file_offset": "0x324c",
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
  "DAT_or_PTR_00013250": {
    "elf_va": "0x3250",
    "file_offset": "0x3250",
    "raw_u32": "0x4a38",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a38",
    "target_string": "PDK_SwitchBIOSFlash"
  },
  "DAT_or_PTR_00013254": {
    "elf_va": "0x3254",
    "file_offset": "0x3254",
    "raw_u32": "0x4a4c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a4c",
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
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013248,DAT_00013244,0xa9,DAT_00013240,param_1);
  iVar1 = dlopen(DAT_0001324c,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013250), pcVar2 == (code *)0x0)) {
    iVar4 = -1;
  }
  else {
    iVar3 = (*pcVar2)(param_1);
    iVar4 = 0;
    if (iVar3 != 0) {
      dlclose(iVar1);
      puts(DAT_00013254);
      return iVar3;
    }
  }
  dlclose(iVar1);
  return iVar4;
}

