/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00010fdc": {
    "elf_va": "0xfdc",
    "file_offset": "0xfdc",
    "raw_u32": "0x148c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x148c",
    "target_string": "/var/pipe/comp_res_pipe"
  },
  "00010fe0": {
    "elf_va": "0xfe0",
    "file_offset": "0xfe0",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00010fe4": {
    "elf_va": "0xfe4",
    "file_offset": "0xfe4",
    "raw_u32": "0x15b0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x15b0",
    "target_string": "Error writing compmngr response command"
  },
  "00010fe8": {
    "elf_va": "0xfe8",
    "file_offset": "0xfe8",
    "raw_u32": "0x1580",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x1580",
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
  
  iVar2 = sigwrap_open(DAT_00010fdc,1);
  iVar1 = DAT_00010fe0;
  if (iVar2 == -1) {
    perror(DAT_00010fe8);
    uVar4 = 0xffffffff;
  }
  else {
    iVar3 = sigwrap_write(iVar2,param_1,DAT_00010fe0);
    if (iVar3 != iVar1) {
      perror(DAT_00010fe4);
    }
    sigwrap_close(iVar2);
    uVar4 = 0;
  }
  return uVar4;
}

