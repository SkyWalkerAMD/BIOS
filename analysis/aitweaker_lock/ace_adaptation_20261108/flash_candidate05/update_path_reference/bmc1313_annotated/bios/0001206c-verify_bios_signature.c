/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012144": {
    "elf_va": "0x2144",
    "file_offset": "0x2144",
    "raw_u32": "0x439c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x439c",
    "target_string": "verify_bios_signature"
  },
  "00012148": {
    "elf_va": "0x2148",
    "file_offset": "0x2148",
    "raw_u32": "0x4e9",
    "target_elf_va": "0x4e9"
  },
  "0001214c": {
    "elf_va": "0x214c",
    "file_offset": "0x214c",
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
  "00012150": {
    "elf_va": "0x2150",
    "file_offset": "0x2150",
    "raw_u32": "0x449c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x449c",
    "target_string": "[%s:%d][%s]\n"
  },
  "00012154": {
    "elf_va": "0x2154",
    "file_offset": "0x2154",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00012158": {
    "elf_va": "0x2158",
    "file_offset": "0x2158",
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
  "0001215c": {
    "elf_va": "0x215c",
    "file_offset": "0x215c",
    "raw_u32": "0x44c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44c8",
    "target_string": "PDK_VerifyBiosSignature"
  },
  "00012160": {
    "elf_va": "0x2160",
    "file_offset": "0x2160",
    "raw_u32": "0x44e0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44e0",
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
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00012150,DAT_0001214c,DAT_00012148,DAT_00012144);
  memset(auStack_10024,0,DAT_00012154);
  iVar1 = dlopen(DAT_00012158,1);
  if (((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_0001215c), pcVar2 == (code *)0x0)) ||
     (iVar3 = (*pcVar2)(), iVar3 == 0)) {
    dlclose(iVar1);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012160);
    uStack_10020 = 0xff;
    uStack_1001c = 0;
    dlclose(iVar1);
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

