/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00010fe0": {
    "elf_va": "0xfe0",
    "file_offset": "0xfe0",
    "raw_u32": "0x1490",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1490",
    "target_string": "/var/pipe/comp_res_pipe"
  },
  "DAT_or_PTR_00010fe4": {
    "elf_va": "0xfe4",
    "file_offset": "0xfe4",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00010fe8": {
    "elf_va": "0xfe8",
    "file_offset": "0xfe8",
    "raw_u32": "0x15b4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x15b4",
    "target_string": "Error writing compmngr response command"
  },
  "DAT_or_PTR_00010fec": {
    "elf_va": "0xfec",
    "file_offset": "0xfec",
    "raw_u32": "0x1584",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1584",
    "target_string": "Error while opening fifo compmngr response pipe"
  }
}
*/

undefined4 send_compmngr_response(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  iVar2 = sigwrap_open(DAT_00010fe0,1);
  iVar1 = DAT_00010fe4;
  if (iVar2 == -1) {
    perror(DAT_00010fec);
    uVar4 = 0xffffffff;
  }
  else {
    iVar3 = sigwrap_write(iVar2,param_1,DAT_00010fe4);
    if (iVar3 != iVar1) {
      perror(DAT_00010fe8);
    }
    sigwrap_close(iVar2);
    uVar4 = 0;
  }
  return uVar4;
}

