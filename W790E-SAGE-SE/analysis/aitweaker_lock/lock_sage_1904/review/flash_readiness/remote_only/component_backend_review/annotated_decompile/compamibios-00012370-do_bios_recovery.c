/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_000124f0": {
    "elf_va": "0x24f0",
    "file_offset": "0x24f0",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "DAT_or_PTR_000124f4": {
    "elf_va": "0x24f4",
    "file_offset": "0x24f4",
    "raw_u32": "0x4418",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4418",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin"
  },
  "DAT_or_PTR_000124f8": {
    "elf_va": "0x24f8",
    "file_offset": "0x24f8",
    "raw_u32": "0x163e8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163e8"
  },
  "DAT_or_PTR_000124fc": {
    "elf_va": "0x24fc",
    "file_offset": "0x24fc",
    "raw_u32": "0x43f",
    "target_elf_va": "0x43f"
  },
  "DAT_or_PTR_00012500": {
    "elf_va": "0x2500",
    "file_offset": "0x2500",
    "raw_u32": "0x4330",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4330",
    "target_string": "compmngramibios.c"
  },
  "DAT_or_PTR_00012504": {
    "elf_va": "0x2504",
    "file_offset": "0x2504",
    "raw_u32": "0x44a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44a0",
    "target_string": "[%s:%d]BIOS Recovery file is Empty !!"
  },
  "DAT_or_PTR_00012508": {
    "elf_va": "0x2508",
    "file_offset": "0x2508",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1655c"
  },
  "DAT_or_PTR_0001250c": {
    "elf_va": "0x250c",
    "file_offset": "0x250c",
    "raw_u32": "0x4514",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4514",
    "target_string": "BIOS Recovery is Failed !!"
  },
  "DAT_or_PTR_00012510": {
    "elf_va": "0x2510",
    "file_offset": "0x2510",
    "raw_u32": "0x437",
    "target_elf_va": "0x437"
  },
  "DAT_or_PTR_00012514": {
    "elf_va": "0x2514",
    "file_offset": "0x2514",
    "raw_u32": "0x4468",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4468",
    "target_string": "[%s:%d]Recovery Image is not present in the location %s"
  },
  "DAT_or_PTR_00012518": {
    "elf_va": "0x2518",
    "file_offset": "0x2518",
    "raw_u32": "0x447",
    "target_elf_va": "0x447"
  },
  "DAT_or_PTR_0001251c": {
    "elf_va": "0x251c",
    "file_offset": "0x251c",
    "raw_u32": "0x44c8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x44c8",
    "target_string": "[%s:%d]Error while finding the BIOS SPI Device"
  },
  "DAT_or_PTR_00012520": {
    "elf_va": "0x2520",
    "file_offset": "0x2520",
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
  "DAT_or_PTR_00012524": {
    "elf_va": "0x2524",
    "file_offset": "0x2524",
    "raw_u32": "0x4530",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4530",
    "target_string": "BIOS Recovery is Successful !!"
  }
}
*/

void do_bios_recovery(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  pthread_t __th;
  undefined4 local_b4;
  char acStack_b0 [64];
  stat sStack_70;
  
  memset(acStack_b0,0,0x40);
  iVar1 = DAT_000124f8;
  local_b4 = 0;
  snprintf(acStack_b0,0x40,DAT_000124f4,*(undefined4 *)(DAT_000124f0 + 0x160));
  *(undefined4 *)(iVar1 + 0x70) = 2;
  iVar4 = __xstat(3,acStack_b0,&sStack_70);
  __th = pthread_self();
  if (iVar4 == 0) {
    if (sStack_70.st_size == 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012504,DAT_00012500,DAT_000124fc);
    }
    else {
      iVar4 = find_bios_spi_device(DAT_00012508);
      if (iVar4 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001251c,DAT_00012500,DAT_00012518);
        *(undefined4 *)(iVar1 + 0x70) = 0;
        pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
        pthread_exit((void *)0x0);
      }
      iVar4 = sigwrap_open(DAT_00012508,2);
      if (iVar4 != -1) {
        iVar4 = flash_bios_image(iVar4,acStack_b0,0,sStack_70.st_size,&local_b4);
        uVar3 = DAT_00012524;
        uVar2 = DAT_0001250c;
        if (iVar4 != 0) {
          *(undefined4 *)(iVar1 + 0x70) = 0;
          IDBG_LINUXAPP_DbgOut(0x86,uVar2);
          pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
          pthread_exit((void *)0x0);
        }
        *(undefined4 *)(iVar1 + 0x70) = 1;
        IDBG_LINUXAPP_DbgOut(0x86,uVar3);
        pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
        pthread_exit((void *)0x0);
      }
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00012520,DAT_00012508);
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00012514,DAT_00012500,DAT_00012510,acStack_b0);
  }
  *(undefined4 *)(iVar1 + 0x70) = 0;
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

