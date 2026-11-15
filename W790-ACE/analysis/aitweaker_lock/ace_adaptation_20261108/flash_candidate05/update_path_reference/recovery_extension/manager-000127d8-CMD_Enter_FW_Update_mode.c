/* Exact ELF literal/relocation map. */
{
  "0001290c": {
    "elf_va": "0x290c",
    "file_offset": "0x290c",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00012910": {
    "elf_va": "0x2910",
    "file_offset": "0x2910",
    "raw_u32": "0x4da0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4da0",
    "target_string": "\n Firmware ID is %d \n"
  },
  "00012914": {
    "elf_va": "0x2914",
    "file_offset": "0x2914",
    "raw_u32": "0x4db8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4db8",
    "target_string": "w"
  },
  "00012918": {
    "elf_va": "0x2918",
    "file_offset": "0x2918",
    "raw_u32": "0x4dbc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4dbc",
    "target_string": "/tmp/fwid"
  },
  "0001291c": {
    "elf_va": "0x291c",
    "file_offset": "0x291c",
    "raw_u32": "0x50fc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x50fc",
    "target_string": "%d"
  },
  "00012920": {
    "elf_va": "0x2920",
    "file_offset": "0x2920",
    "raw_u32": "0x4d88",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d88",
    "target_string": "/var/block_chassis_ops"
  },
  "00012924": {
    "elf_va": "0x2924",
    "file_offset": "0x2924",
    "raw_u32": "0x4d58",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d58",
    "target_string": "Error while entering into fimware update mode\n"
  },
  "00012928": {
    "elf_va": "0x2928",
    "file_offset": "0x2928",
    "raw_u32": "0xffff",
    "target_elf_va": "0xffff"
  }
}

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
  memset(auStack_20028,0,DAT_0001290c);
  memset(auStack_1001c,0,DAT_0001290c);
  iVar2 = send_compmngr_command(auStack_20028,auStack_1001c,0x3c);
  if (iVar2 == 0) {
    if (iStack_10018 == 0) {
      touch(DAT_00012920);
    }
    memcpy(&uStack_2002c,auStack_10012,4);
    uVar1 = uStack_2002c;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012910,uStack_2002c);
    __stream = fopen(DAT_00012918,DAT_00012914);
    fprintf(__stream,DAT_0001291c,uVar1);
    fclose(__stream);
    memcpy(param_1,auStack_1001c,DAT_0001290c);
    return param_1;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012924);
  iStack_10018 = DAT_00012928;
  memcpy(param_1,auStack_1001c,DAT_0001290c);
  return param_1;
}

