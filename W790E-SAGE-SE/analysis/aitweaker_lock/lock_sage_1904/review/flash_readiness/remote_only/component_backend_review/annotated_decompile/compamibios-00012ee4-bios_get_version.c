/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013168": {
    "elf_va": "0x3168",
    "file_offset": "0x3168",
    "raw_u32": "0x4260",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4260",
    "target_string": "bios_get_version"
  },
  "DAT_or_PTR_0001316c": {
    "elf_va": "0x316c",
    "file_offset": "0x316c",
    "raw_u32": "0x48e4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x48e4",
    "target_string": "[%s]\n"
  },
  "DAT_or_PTR_00013170": {
    "elf_va": "0x3170",
    "file_offset": "0x3170",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "DAT_or_PTR_00013174": {
    "elf_va": "0x3174",
    "file_offset": "0x3174",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_FirmwareID",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_00013178": {
    "elf_va": "0x3178",
    "file_offset": "0x3178",
    "raw_u32": "0x48ec",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x48ec",
    "target_string": "Failed ID %d : %d\n"
  },
  "DAT_or_PTR_0001317c": {
    "elf_va": "0x317c",
    "file_offset": "0x317c",
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
  "DAT_or_PTR_00013180": {
    "elf_va": "0x3180",
    "file_offset": "0x3180",
    "raw_u32": "0x4924",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4924",
    "target_string": "PDK_GetASUSBIOSInfo"
  },
  "DAT_or_PTR_00013184": {
    "elf_va": "0x3184",
    "file_offset": "0x3184",
    "raw_u32": "0x4938",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4938",
    "target_string": "/var/bios.bin"
  },
  "DAT_or_PTR_00013188": {
    "elf_va": "0x3188",
    "file_offset": "0x3188",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_ASUSBiosHeader",
      "symbol_va": 91268,
      "symbol_defined": true
    },
    "target_elf_va": "0x16484"
  },
  "DAT_or_PTR_0001318c": {
    "elf_va": "0x318c",
    "file_offset": "0x318c",
    "raw_u32": "0x49c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x49c8",
    "target_string": "===BIOS File Info==="
  },
  "DAT_or_PTR_00013190": {
    "elf_va": "0x3190",
    "file_offset": "0x3190",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1655c"
  },
  "DAT_or_PTR_00013194": {
    "elf_va": "0x3194",
    "file_offset": "0x3194",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_mtdASUSBiosHeader",
      "symbol_va": 91504,
      "symbol_defined": true
    },
    "target_elf_va": "0x16570"
  },
  "DAT_or_PTR_00013198": {
    "elf_va": "0x3198",
    "file_offset": "0x3198",
    "raw_u32": "0x4a0c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a0c",
    "target_string": "===MTD BIOS Info==="
  },
  "DAT_or_PTR_0001319c": {
    "elf_va": "0x319c",
    "file_offset": "0x319c",
    "raw_u32": "0x4900",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4900",
    "target_string": "Failed in getting bios file size\n"
  },
  "DAT_or_PTR_000131a0": {
    "elf_va": "0x31a0",
    "file_offset": "0x31a0",
    "raw_u32": "0x49e0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x49e0",
    "target_string": "Unable to get BIOS Version from MTD device\n"
  },
  "DAT_or_PTR_000131a4": {
    "elf_va": "0x31a4",
    "file_offset": "0x31a4",
    "raw_u32": "0x499c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x499c",
    "target_string": "Unable to get BIOS Version the bios file\n"
  },
  "DAT_or_PTR_000131a8": {
    "elf_va": "0x31a8",
    "file_offset": "0x31a8",
    "raw_u32": "0x496c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x496c",
    "target_string": "[W790] Search bios file from 48MB (0x3000000)"
  },
  "DAT_or_PTR_000131ac": {
    "elf_va": "0x31ac",
    "file_offset": "0x31ac",
    "raw_u32": "0x4948",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4948",
    "target_string": "Error while opening the bios file"
  },
  "DAT_or_PTR_000131b0": {
    "elf_va": "0x31b0",
    "file_offset": "0x31b0",
    "raw_u32": "0x44f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44f8",
    "target_string": "ERROR: open failed (%s)\n"
  }
}
*/

undefined4
bios_get_version(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  int iStack_1003c;
  int iStack_10038;
  undefined2 auStack_10034 [2];
  undefined4 uStack_10030;
  short sStack_1002c;
  undefined1 auStack_1002a [203];
  undefined1 auStack_ff5f [65339];
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  iStack_1003c = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x86,DAT_0001316c,DAT_00013168);
  ClearASUSBiosHeader();
  memset(auStack_10034,0,DAT_00013170);
  memcpy(&iStack_10038,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10038 != *DAT_00013174) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013178);
    sStack_1002c = 0;
    uStack_10030 = 6;
    goto LAB_00012f6c;
  }
  iVar1 = get_bios_file_size(&iStack_1003c);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_0001319c);
    sStack_1002c = 0;
    uStack_10030 = 0xff;
    goto LAB_00012f6c;
  }
  iVar1 = dlopen(DAT_0001317c,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013180), pcVar2 == (code *)0x0)) {
LAB_00013098:
    dlclose(iVar1);
  }
  else {
    iVar3 = sigwrap_open(DAT_00013184,2);
    if (iVar3 < 0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000131ac);
    }
    else {
      if (iStack_1003c == 0x4000000) {
        puts(DAT_000131a8);
        iVar4 = (*pcVar2)(iVar3,iStack_1003c + -0x3000000,DAT_00013188,0x3000000);
      }
      else {
        iVar4 = (*pcVar2)(iVar3,iStack_1003c,DAT_00013188,0);
      }
      if (iVar4 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000131a4);
        uStack_10030 = 0xf1;
        sStack_1002c = 0;
        close(iVar3);
        dlclose(iVar1);
        goto LAB_00012f6c;
      }
      puts(DAT_0001318c);
      PrintBiosHeader(DAT_00013188);
      sigwrap_close(iVar3);
      iVar3 = sigwrap_open(DAT_00013190,2);
      if (iVar3 != -1) {
        iVar4 = (*pcVar2)(iVar3,0x1000000,DAT_00013194,0x3000000);
        if (iVar4 != 0) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_000131a0);
          uStack_10030 = 0xf0;
        }
        puts(DAT_00013198);
        PrintBiosHeader(DAT_00013194);
        memcpy(auStack_1002a,DAT_00013194,0xcb);
        memcpy(auStack_ff5f,DAT_00013188,0xcb);
        sStack_1002c = sStack_1002c + 0x196;
        sigwrap_close(iVar3);
        goto LAB_00013098;
      }
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000131b0,DAT_00013190);
    }
    sStack_1002c = 0;
    uStack_10030 = 0xff;
    dlclose(iVar1);
  }
LAB_00012f6c:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

