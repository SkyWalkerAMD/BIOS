/* Exact ELF literal/relocation map. */
{
  "00011e64": {
    "elf_va": "0x11e64",
    "file_offset": "0x1e64",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "00011e68": {
    "elf_va": "0x11e68",
    "file_offset": "0x1e68",
    "raw_u32": "0x11f94",
    "target_elf_va": "0x11f94",
    "target_string": "compmanager.c"
  },
  "00011e6c": {
    "elf_va": "0x11e6c",
    "file_offset": "0x1e6c",
    "raw_u32": "0x12210",
    "target_elf_va": "0x12210",
    "target_string": "[%s:%d]Processing the Command Request for Component %d and Command %d"
  },
  "00011e70": {
    "elf_va": "0x11e70",
    "file_offset": "0x1e70",
    "raw_u32": "0x12368",
    "target_elf_va": "0x12368",
    "target_string": "[%s:%d]Error while Adding the CompBook Event Entry"
  },
  "00011e74": {
    "elf_va": "0x11e74",
    "file_offset": "0x1e74",
    "raw_u32": "0x12330",
    "target_elf_va": "0x12330",
    "target_string": "[%s:%d]Error while clearing the CompBook Event Repos"
  },
  "00011e78": {
    "elf_va": "0x11e78",
    "file_offset": "0x1e78",
    "raw_u32": "0x122f0",
    "target_elf_va": "0x122f0",
    "target_string": "[%s:%d]Error while getting the CompBook event repos information"
  },
  "00011e7c": {
    "elf_va": "0x11e7c",
    "file_offset": "0x1e7c",
    "raw_u32": "0x122b8",
    "target_elf_va": "0x122b8",
    "target_string": "[%s:%d]Error while Exiting from firmware update mode "
  },
  "00011e80": {
    "elf_va": "0x11e80",
    "file_offset": "0x1e80",
    "raw_u32": "0x14f",
    "target_elf_va": "0x14f"
  },
  "00011e84": {
    "elf_va": "0x11e84",
    "file_offset": "0x1e84",
    "raw_u32": "0xfffc",
    "target_elf_va": "0xfffc"
  },
  "00011e88": {
    "elf_va": "0x11e88",
    "file_offset": "0x1e88",
    "raw_u32": "0x187",
    "target_elf_va": "0x187"
  },
  "00011e8c": {
    "elf_va": "0x11e8c",
    "file_offset": "0x1e8c",
    "raw_u32": "0x179",
    "target_elf_va": "0x179"
  },
  "00011e90": {
    "elf_va": "0x11e90",
    "file_offset": "0x1e90",
    "raw_u32": "0x172",
    "target_elf_va": "0x172"
  },
  "00011e94": {
    "elf_va": "0x11e94",
    "file_offset": "0x1e94",
    "raw_u32": "0x16b",
    "target_elf_va": "0x16b"
  },
  "00011e98": {
    "elf_va": "0x11e98",
    "file_offset": "0x1e98",
    "raw_u32": "0x12280",
    "target_elf_va": "0x12280",
    "target_string": "[%s:%d]Error while Entering into firmware update mode "
  },
  "00011e9c": {
    "elf_va": "0x11e9c",
    "file_offset": "0x1e9c",
    "raw_u32": "0x23998",
    "target_elf_va": "0x23998"
  },
  "00011ea0": {
    "elf_va": "0x11ea0",
    "file_offset": "0x1ea0",
    "raw_u32": "0x239e0",
    "target_elf_va": "0x239e0"
  },
  "00011ea4": {
    "elf_va": "0x11ea4",
    "file_offset": "0x1ea4",
    "raw_u32": "0x12258",
    "target_elf_va": "0x12258",
    "target_string": "Error while processing the command %d"
  },
  "00011ea8": {
    "elf_va": "0x11ea8",
    "file_offset": "0x1ea8",
    "raw_u32": "0x121f8",
    "target_elf_va": "0x121f8",
    "target_string": "/var/pipe/comp_req_pipe"
  },
  "00011eac": {
    "elf_va": "0x11eac",
    "file_offset": "0x1eac",
    "raw_u32": "0x14b",
    "target_elf_va": "0x14b"
  },
  "00011eb0": {
    "elf_va": "0x11eb0",
    "file_offset": "0x1eb0",
    "raw_u32": "0x121d0",
    "target_elf_va": "0x121d0",
    "target_string": "[%s:%d]Error in reading from pipe %s\n"
  },
  "00011eb4": {
    "elf_va": "0x11eb4",
    "file_offset": "0x1eb4",
    "raw_u32": "0x1239c",
    "target_elf_va": "0x1239c",
    "target_string": "Invalid Command Parameter 0x%x"
  }
}

undefined4 FUN_00011bcc(void)

{
  char *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  code *pcVar10;
  uint uStack_20038;
  uint uStack_20034;
  undefined4 uStack_10034;
  undefined4 uStack_10030;
  undefined4 uStack_1002c;
  undefined4 uStack_10028;
  undefined1 auStack_10024 [65536];
  
  memset(&uStack_10034,0,DAT_00011e64);
  uVar7 = DAT_00011e7c;
  uVar6 = DAT_00011e78;
  uVar5 = DAT_00011e74;
  uVar4 = DAT_00011e70;
  uVar3 = DAT_00011e6c;
  uVar2 = DAT_00011e68;
LAB_00011c0c:
  do {
    do {
      while( true ) {
        iVar8 = FUN_00011614(&uStack_10034);
        if (iVar8 < 0) {
          uStack_20038 = DAT_00011ea8;
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011eb0,DAT_00011e68,DAT_00011eac);
          return 0;
        }
        uStack_20034 = uStack_10034 & 0xffff;
        uStack_20038 = uStack_10034 >> 0x10 & 0xff;
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar3,uVar2,DAT_00011e80);
        if (uStack_10034._2_1_ != '\0') break;
        switch(uStack_10034 & 0xffff) {
        case 1:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_0001192c(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011e98,uVar2,DAT_00011e94);
          }
          break;
        case 2:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_00011aa8(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar7,uVar2,DAT_00011e90);
          }
          break;
        case 3:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_00011704(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar6,uVar2,DAT_00011e8c);
          }
          break;
        case 4:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_00011878(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar4,uVar2,DAT_00011e88);
          }
          break;
        case 5:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_000117c8(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar5,uVar2,0x180);
          }
          break;
        default:
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00011eb4);
        }
      }
    } while (*DAT_00011e9c < 1);
    if (*(char *)(DAT_00011ea0 + 0xff) == uStack_10034._2_1_) {
      iVar9 = 0;
    }
    else {
      iVar9 = 0;
      iVar8 = DAT_00011ea0;
      do {
        iVar9 = iVar9 + 1;
        if (iVar9 == *DAT_00011e9c) goto LAB_00011c0c;
        pcVar1 = (char *)(iVar8 + 0x213);
        iVar8 = iVar8 + 0x114;
      } while (*pcVar1 != uStack_10034._2_1_);
    }
    pcVar10 = *(code **)(DAT_00011ea0 + iVar9 * 0x114 + 0x10c);
    if (pcVar10 != (code *)0x0) {
      memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
      iVar8 = (*pcVar10)(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
      if (iVar8 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ea4,uStack_10034 & 0xffff);
      }
    }
  } while( true );
}

