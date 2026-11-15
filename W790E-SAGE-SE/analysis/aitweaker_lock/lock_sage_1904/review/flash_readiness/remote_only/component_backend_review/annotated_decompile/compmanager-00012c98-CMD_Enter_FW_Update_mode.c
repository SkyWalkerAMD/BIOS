/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00012dcc": {
    "elf_va": "0x2dcc",
    "file_offset": "0x2dcc",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00012dd0": {
    "elf_va": "0x2dd0",
    "file_offset": "0x2dd0",
    "raw_u32": "0x5610",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5610",
    "target_string": "\n Firmware ID is %d \n"
  },
  "DAT_or_PTR_00012dd4": {
    "elf_va": "0x2dd4",
    "file_offset": "0x2dd4",
    "raw_u32": "0x5628",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5628",
    "target_string": "w"
  },
  "DAT_or_PTR_00012dd8": {
    "elf_va": "0x2dd8",
    "file_offset": "0x2dd8",
    "raw_u32": "0x562c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x562c",
    "target_string": "/tmp/fwid"
  },
  "DAT_or_PTR_00012ddc": {
    "elf_va": "0x2ddc",
    "file_offset": "0x2ddc",
    "raw_u32": "0x59ac",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x59ac",
    "target_string": "%d"
  },
  "DAT_or_PTR_00012de0": {
    "elf_va": "0x2de0",
    "file_offset": "0x2de0",
    "raw_u32": "0x55f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x55f8",
    "target_string": "/var/block_chassis_ops"
  },
  "DAT_or_PTR_00012de4": {
    "elf_va": "0x2de4",
    "file_offset": "0x2de4",
    "raw_u32": "0x55c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x55c8",
    "target_string": "Error while entering into fimware update mode\n"
  },
  "DAT_or_PTR_00012de8": {
    "elf_va": "0x2de8",
    "file_offset": "0x2de8",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}
*/

void * CMD_Enter_FW_Update_mode(void *param_1)

{
  undefined4 uVar1;
  int iVar2;
  FILE *__stream;
  undefined4 uStack_2002c;
  undefined1 auStack_20028 [65548];
  undefined1 auStack_1001c [4];
  int iStack_10018;
  undefined1 auStack_10012 [65538];
  
  uStack_2002c = 0;
  memset(auStack_20028,0,DAT_00012dcc);
  memset(auStack_1001c,0,DAT_00012dcc);
  iVar2 = send_compmngr_command(auStack_20028,auStack_1001c,0x3c);
  if (iVar2 == 0) {
    if (iStack_10018 == 0) {
      touch(DAT_00012de0);
    }
    memcpy(&uStack_2002c,auStack_10012,4);
    uVar1 = uStack_2002c;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012dd0,uStack_2002c);
    __stream = fopen(DAT_00012dd8,DAT_00012dd4);
    fprintf(__stream,DAT_00012ddc,uVar1);
    fclose(__stream);
    memcpy(param_1,auStack_1001c,DAT_00012dcc);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012de4);
  iStack_10018 = DAT_00012de8;
  memcpy(param_1,auStack_1001c,DAT_00012dcc);
  return param_1;
}

