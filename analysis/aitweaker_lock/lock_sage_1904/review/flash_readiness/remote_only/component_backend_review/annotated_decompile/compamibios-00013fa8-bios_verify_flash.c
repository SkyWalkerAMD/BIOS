/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00014144": {
    "elf_va": "0x4144",
    "file_offset": "0x4144",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_00014148": {
    "elf_va": "0x4148",
    "file_offset": "0x4148",
    "raw_u32": "0x43f0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x43f0",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin_tmp"
  },
  "DAT_or_PTR_0001414c": {
    "elf_va": "0x414c",
    "file_offset": "0x414c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1655c"
  },
  "DAT_or_PTR_00014150": {
    "elf_va": "0x4150",
    "file_offset": "0x4150",
    "raw_u32": "0x16460",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16460"
  },
  "DAT_or_PTR_00014154": {
    "elf_va": "0x4154",
    "file_offset": "0x4154",
    "raw_u32": "0x42f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x42f8",
    "target_string": "bios_verify_flash"
  },
  "DAT_or_PTR_00014158": {
    "elf_va": "0x4158",
    "file_offset": "0x4158",
    "raw_u32": "0x4fb8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4fb8",
    "target_string": "[%s] FlashOffset = 0x%X, Size = 0x%X\n"
  },
  "DAT_or_PTR_0001415c": {
    "elf_va": "0x415c",
    "file_offset": "0x415c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_corefeatures",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_00014160": {
    "elf_va": "0x4160",
    "file_offset": "0x4160",
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
  "DAT_or_PTR_00014164": {
    "elf_va": "0x4164",
    "file_offset": "0x4164",
    "raw_u32": "0x4fe0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4fe0",
    "target_string": "Error while verify the BIOS Image"
  },
  "DAT_or_PTR_00014168": {
    "elf_va": "0x4168",
    "file_offset": "0x4168",
    "raw_u32": "0x44f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44f8",
    "target_string": "ERROR: open failed (%s)\n"
  },
  "DAT_or_PTR_0001416c": {
    "elf_va": "0x416c",
    "file_offset": "0x416c",
    "raw_u32": "0x5004",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5004",
    "target_string": "mv %s %s"
  },
  "DAT_or_PTR_00014170": {
    "elf_va": "0x4170",
    "file_offset": "0x4170",
    "raw_u32": "0x443c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x443c",
    "target_string": "Error while taking the BIOS Recovery Image"
  }
}
*/

void bios_verify_flash(void *param_1)

{
  int iVar1;
  pthread_t __th;
  int iVar2;
  int iVar3;
  undefined4 local_c0;
  undefined4 local_bc;
  char acStack_b0 [64];
  char acStack_70 [88];
  
  memset(acStack_b0,0,0x40);
  memset(acStack_70,0,0x58);
  memcpy(&local_c0,param_1,0x10);
  snprintf(acStack_b0,0x40,DAT_00014148,*(undefined4 *)(DAT_00014144 + 0x160));
  iVar1 = sigwrap_open(DAT_0001414c,2);
  __th = pthread_self();
  iVar3 = DAT_00014150;
  if (iVar1 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014168,DAT_0001414c);
    ActiveHostSPIDriver(1);
    *(undefined4 *)(DAT_00014150 + 4) = 0xffffffff;
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014158,DAT_00014154,local_c0,local_bc);
  iVar2 = verify_bios_img(iVar1,local_c0,local_bc,iVar3 + 4);
  if (iVar2 == 0) {
    sigwrap_close(iVar1);
    ActiveHostSPIDriver(1);
    if ((*(int *)(iVar3 + 4) == -1) || (*(int *)(DAT_0001415c + 0x350) != 1)) {
      unlink(DAT_00014160);
    }
    else {
      snprintf(acStack_70,0x58,DAT_0001416c,DAT_00014160,acStack_b0);
      iVar3 = safe_system(acStack_70);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00014170);
      }
    }
    write_forcedUpdate_flag();
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014164);
  ActiveHostSPIDriver(1);
  *(undefined4 *)(iVar3 + 4) = 0xffffffff;
  sigwrap_close(iVar1);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

