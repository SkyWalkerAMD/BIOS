/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.
{
  "DAT_or_PTR_00013aa8": {
    "elf_va": "0x3aa8",
    "file_offset": "0x3aa8",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91484,
      "symbol_defined": true
    },
    "target_elf_va": "0x1655c"
  },
  "DAT_or_PTR_00013aac": {
    "elf_va": "0x3aac",
    "file_offset": "0x3aac",
    "raw_u32": "0x16460",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16460"
  },
  "DAT_or_PTR_00013ab0": {
    "elf_va": "0x3ab0",
    "file_offset": "0x3ab0",
    "raw_u32": "0x42bc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x42bc",
    "target_string": "bios_flash"
  },
  "DAT_or_PTR_00013ab4": {
    "elf_va": "0x3ab4",
    "file_offset": "0x3ab4",
    "raw_u32": "0x4d60",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d60",
    "target_string": "[%s] FlashOffset = 0x%x, Size = 0x%x\n"
  },
  "DAT_or_PTR_00013ab8": {
    "elf_va": "0x3ab8",
    "file_offset": "0x3ab8",
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
  "DAT_or_PTR_00013abc": {
    "elf_va": "0x3abc",
    "file_offset": "0x3abc",
    "raw_u32": "0x4d88",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4d88",
    "target_string": "BIOS Flashing is Failed !!"
  },
  "DAT_or_PTR_00013ac0": {
    "elf_va": "0x3ac0",
    "file_offset": "0x3ac0",
    "raw_u32": "0x4da4",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4da4",
    "target_string": "Bios START update done FlashOffset %d: SizeToWrite %d\n"
  },
  "DAT_or_PTR_00013ac4": {
    "elf_va": "0x3ac4",
    "file_offset": "0x3ac4",
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

void bios_flash(void *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  pthread_t __th;
  int iVar4;
  undefined4 local_30;
  undefined4 local_2c;
  
  memcpy(&local_30,param_1,0x10);
  iVar3 = sigwrap_open(DAT_00013aa8,2);
  __th = pthread_self();
  puVar1 = DAT_00013aac;
  if (iVar3 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013ac4,DAT_00013aa8);
    *DAT_00013aac = 0xffffffff;
    ActiveHostSPIDriver(1);
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013ab4,DAT_00013ab0,local_30,local_2c);
  iVar4 = flash_bios_image(iVar3,DAT_00013ab8,local_30,local_2c,puVar1);
  if (iVar4 != 0) {
    ActiveHostSPIDriver(1);
    uVar2 = DAT_00013abc;
    *puVar1 = 0xffffffff;
    IDBG_LINUXAPP_DbgOut(0x86,uVar2);
    sigwrap_close(iVar3);
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  sigwrap_close(iVar3);
  uVar2 = DAT_00013ac0;
  *puVar1 = 100;
  IDBG_LINUXAPP_DbgOut(0x86,uVar2,local_30,local_2c);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

