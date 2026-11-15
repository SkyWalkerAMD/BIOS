/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000111c4": {
    "elf_va": "0x11c4",
    "file_offset": "0x11c4",
    "raw_u32": "0x1eb8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1eb8",
    "target_string": "hosthelper.c"
  },
  "000111c8": {
    "elf_va": "0x11c8",
    "file_offset": "0x11c8",
    "raw_u32": "0x1f98",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1f98",
    "target_string": "[%s:%d]Error in sending chassis power cycle IPMI command \n"
  },
  "000111cc": {
    "elf_va": "0x11cc",
    "file_offset": "0x11cc",
    "raw_u32": "0x1f68",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1f68",
    "target_string": "[%s:%d]Error in sending IPMI command raw %x %x "
  },
  "000111d0": {
    "elf_va": "0x11d0",
    "file_offset": "0x11d0",
    "raw_u32": "0x1fd4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1fd4",
    "target_string": "[%s:%d]Error in sending chassis power on IPMI command \n"
  }
}
*/

undefined4 RebootHost(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 local_24 [4];
  undefined1 auStack_20 [4];
  undefined4 local_1c;
  undefined1 uStack_18;
  byte local_17;
  
  local_1c = 5;
  iVar1 = SendRawIPMICommand(0,1,0,0,&uStack_18,&local_1c,0x1e);
  if (iVar1 == 0) {
    if ((local_17 & 1) == 0) {
      local_24[0] = 1;
      local_1c = 1;
      iVar1 = SendRawIPMICommand(0,2,local_24,1,auStack_20,&local_1c,0x1e);
      if (iVar1 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000111d0,DAT_000111c4,0x90);
        return 0xffffffff;
      }
    }
    else {
      local_24[0] = 2;
      local_1c = 1;
      iVar1 = SendRawIPMICommand(0,2,local_24,1,auStack_20,&local_1c,0x1e);
      if (iVar1 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000111c8,DAT_000111c4,0x84);
        return 0xffffffff;
      }
    }
    uVar2 = 0;
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000111cc,DAT_000111c4,0x76,0,1);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

