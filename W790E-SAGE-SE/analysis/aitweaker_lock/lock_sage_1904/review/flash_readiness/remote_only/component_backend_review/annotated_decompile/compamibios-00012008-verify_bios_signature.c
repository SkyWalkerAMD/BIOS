/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000120e0": {
    "elf_va": "0x20e0",
    "file_offset": "0x20e0",
    "raw_u32": "0x41f4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x41f4",
    "target_string": "verify_bios_signature"
  },
  "DAT_or_PTR_000120e4": {
    "elf_va": "0x20e4",
    "file_offset": "0x20e4",
    "raw_u32": "0x496",
    "target_elf_va": "0x496"
  },
  "DAT_or_PTR_000120e8": {
    "elf_va": "0x20e8",
    "file_offset": "0x20e8",
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
  "DAT_or_PTR_000120ec": {
    "elf_va": "0x20ec",
    "file_offset": "0x20ec",
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
  "DAT_or_PTR_000120f0": {
    "elf_va": "0x20f0",
    "file_offset": "0x20f0",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_000120f4": {
    "elf_va": "0x20f4",
    "file_offset": "0x20f4",
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
  "DAT_or_PTR_000120f8": {
    "elf_va": "0x20f8",
    "file_offset": "0x20f8",
    "raw_u32": "0x4370",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4370",
    "target_string": "PDK_VerifyBiosSignature"
  },
  "DAT_or_PTR_000120fc": {
    "elf_va": "0x20fc",
    "file_offset": "0x20fc",
    "raw_u32": "0x4388",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4388",
    "target_string": "BIOS signature verify fail\n"
  }
}
*/

undefined4 verify_bios_signature(undefined2 param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000120ec,DAT_000120e8,DAT_000120e4,DAT_000120e0);
  memset(auStack_10024,0,DAT_000120f0);
  iVar1 = dlopen(DAT_000120f4,1);
  if (((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_000120f8), pcVar2 == (code *)0x0)) ||
     (iVar3 = (*pcVar2)(), iVar3 == 0)) {
    dlclose(iVar1);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000120fc);
    uStack_10020 = 0xff;
    uStack_1001c = 0;
    dlclose(iVar1);
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

