/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000141f0": {
    "elf_va": "0x41f0",
    "file_offset": "0x41f0",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "000141f4": {
    "elf_va": "0x41f4",
    "file_offset": "0x41f4",
    "raw_u32": "0x4548",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4548",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin_tmp"
  },
  "000141f8": {
    "elf_va": "0x41f8",
    "file_offset": "0x41f8",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91548,
      "symbol_defined": true
    },
    "target_elf_va": "0x1659c"
  },
  "000141fc": {
    "elf_va": "0x41fc",
    "file_offset": "0x41fc",
    "raw_u32": "0x164a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a0"
  },
  "00014200": {
    "elf_va": "0x4200",
    "file_offset": "0x4200",
    "raw_u32": "0x4450",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4450",
    "target_string": "bios_verify_flash"
  },
  "00014204": {
    "elf_va": "0x4204",
    "file_offset": "0x4204",
    "raw_u32": "0x51dc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x51dc",
    "target_string": "[%s] FlashOffset = 0x%X, Size = 0x%X\n"
  },
  "00014208": {
    "elf_va": "0x4208",
    "file_offset": "0x4208",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_corefeatures",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "0001420c": {
    "elf_va": "0x420c",
    "file_offset": "0x420c",
    "raw_u32": "0x4d10",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d10",
    "target_string": "/var/bios.bin"
  },
  "00014210": {
    "elf_va": "0x4210",
    "file_offset": "0x4210",
    "raw_u32": "0x5204",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5204",
    "target_string": "Error while verify the BIOS Image"
  },
  "00014214": {
    "elf_va": "0x4214",
    "file_offset": "0x4214",
    "raw_u32": "0x4650",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4650",
    "target_string": "ERROR: open failed (%s)\n"
  },
  "00014218": {
    "elf_va": "0x4218",
    "file_offset": "0x4218",
    "raw_u32": "0x5228",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x5228",
    "target_string": "mv %s %s"
  },
  "0001421c": {
    "elf_va": "0x421c",
    "file_offset": "0x421c",
    "raw_u32": "0x4594",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4594",
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
  undefined4 local_a8;
  undefined4 local_a4;
  char acStack_98 [64];
  char acStack_58 [64];
  
  memset(acStack_98,0,0x40);
  memset(acStack_58,0,0x40);
  memcpy(&local_a8,param_1,0x10);
  snprintf(acStack_98,0x40,DAT_000141f4,*(undefined4 *)(DAT_000141f0 + 0x160));
  iVar1 = sigwrap_open(DAT_000141f8,2);
  __th = pthread_self();
  iVar3 = DAT_000141fc;
  if (iVar1 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014214,DAT_000141f8);
    ActiveHostSPIDriver(1);
    *(undefined4 *)(DAT_000141fc + 4) = 0xffffffff;
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014204,DAT_00014200,local_a8,local_a4);
  iVar2 = verify_bios_img(iVar1,local_a8,local_a4,iVar3 + 4);
  if (iVar2 == 0) {
    sigwrap_close(iVar1);
    ActiveHostSPIDriver(1);
    if ((*(int *)(iVar3 + 4) == -1) || (*(int *)(DAT_00014208 + 0x34c) != 1)) {
      unlink(DAT_0001420c);
    }
    else {
      snprintf(acStack_58,0x40,DAT_00014218,DAT_0001420c,acStack_98);
      iVar3 = safe_system(acStack_58);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_0001421c);
      }
    }
    write_forcedUpdate_flag();
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014210);
  ActiveHostSPIDriver(1);
  *(undefined4 *)(iVar3 + 4) = 0xffffffff;
  sigwrap_close(iVar1);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

