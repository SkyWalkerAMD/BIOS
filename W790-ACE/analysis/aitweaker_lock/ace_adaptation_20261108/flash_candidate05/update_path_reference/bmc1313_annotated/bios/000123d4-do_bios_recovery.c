/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00012554": {
    "elf_va": "0x2554",
    "file_offset": "0x2554",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "g_coremacros",
      "symbol_va": 0,
      "symbol_defined": false
    }
  },
  "00012558": {
    "elf_va": "0x2558",
    "file_offset": "0x2558",
    "raw_u32": "0x4570",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4570",
    "target_string": "/mnt/sdmmc0p%d/recovery_bios.bin"
  },
  "0001255c": {
    "elf_va": "0x255c",
    "file_offset": "0x255c",
    "raw_u32": "0x163f0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x163f0"
  },
  "00012560": {
    "elf_va": "0x2560",
    "file_offset": "0x2560",
    "raw_u32": "0x492",
    "target_elf_va": "0x492"
  },
  "00012564": {
    "elf_va": "0x2564",
    "file_offset": "0x2564",
    "raw_u32": "0x4488",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4488",
    "target_string": "compmngramibios.c"
  },
  "00012568": {
    "elf_va": "0x2568",
    "file_offset": "0x2568",
    "raw_u32": "0x45f8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x45f8",
    "target_string": "[%s:%d]BIOS Recovery file is Empty !!"
  },
  "0001256c": {
    "elf_va": "0x256c",
    "file_offset": "0x256c",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91548,
      "symbol_defined": true
    },
    "target_elf_va": "0x1659c"
  },
  "00012570": {
    "elf_va": "0x2570",
    "file_offset": "0x2570",
    "raw_u32": "0x466c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x466c",
    "target_string": "BIOS Recovery is Failed !!"
  },
  "00012574": {
    "elf_va": "0x2574",
    "file_offset": "0x2574",
    "raw_u32": "0x48a",
    "target_elf_va": "0x48a"
  },
  "00012578": {
    "elf_va": "0x2578",
    "file_offset": "0x2578",
    "raw_u32": "0x45c0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x45c0",
    "target_string": "[%s:%d]Recovery Image is not present in the location %s"
  },
  "0001257c": {
    "elf_va": "0x257c",
    "file_offset": "0x257c",
    "raw_u32": "0x49a",
    "target_elf_va": "0x49a"
  },
  "00012580": {
    "elf_va": "0x2580",
    "file_offset": "0x2580",
    "raw_u32": "0x4620",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4620",
    "target_string": "[%s:%d]Error while finding the BIOS SPI Device"
  },
  "00012584": {
    "elf_va": "0x2584",
    "file_offset": "0x2584",
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
  "00012588": {
    "elf_va": "0x2588",
    "file_offset": "0x2588",
    "raw_u32": "0x4688",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4688",
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
  iVar1 = DAT_0001255c;
  local_b4 = 0;
  snprintf(acStack_b0,0x40,DAT_00012558,*(undefined4 *)(DAT_00012554 + 0x160));
  *(undefined4 *)(iVar1 + 0x60) = 2;
  iVar4 = __xstat(3,acStack_b0,&sStack_70);
  __th = pthread_self();
  if (iVar4 == 0) {
    if (sStack_70.st_size == 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012568,DAT_00012564,DAT_00012560);
    }
    else {
      iVar4 = find_bios_spi_device(DAT_0001256c);
      if (iVar4 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00012580,DAT_00012564,DAT_0001257c);
        *(undefined4 *)(iVar1 + 0x60) = 0;
        pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
        pthread_exit((void *)0x0);
      }
      iVar4 = sigwrap_open(DAT_0001256c,2);
      if (iVar4 != -1) {
        iVar4 = flash_bios_image(iVar4,acStack_b0,0,sStack_70.st_size,&local_b4);
        uVar3 = DAT_00012588;
        uVar2 = DAT_00012570;
        if (iVar4 != 0) {
          *(undefined4 *)(iVar1 + 0x60) = 0;
          IDBG_LINUXAPP_DbgOut(0x86,uVar2);
          pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
          pthread_exit((void *)0x0);
        }
        *(undefined4 *)(iVar1 + 0x60) = 1;
        IDBG_LINUXAPP_DbgOut(0x86,uVar3);
        pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
        pthread_exit((void *)0x0);
      }
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00012584,DAT_0001256c);
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00012578,DAT_00012564,DAT_00012574,acStack_b0);
  }
  *(undefined4 *)(iVar1 + 0x60) = 0;
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

