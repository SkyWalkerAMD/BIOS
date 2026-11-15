/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "00013910": {
    "elf_va": "0x3910",
    "file_offset": "0x3910",
    "raw_u32": "0x0",
    "relocation": {
      "type": 2,
      "symbol": "MTD_Device",
      "symbol_va": 91548,
      "symbol_defined": true
    },
    "target_elf_va": "0x1659c"
  },
  "00013914": {
    "elf_va": "0x3914",
    "file_offset": "0x3914",
    "raw_u32": "0x164a0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x164a0"
  },
  "00013918": {
    "elf_va": "0x3918",
    "file_offset": "0x3918",
    "raw_u32": "0x441c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x441c",
    "target_string": "bios_flash"
  },
  "0001391c": {
    "elf_va": "0x391c",
    "file_offset": "0x391c",
    "raw_u32": "0x4e6c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4e6c",
    "target_string": "[%s] FlashOffset = 0x%x, Size = 0x%x\n"
  },
  "00013920": {
    "elf_va": "0x3920",
    "file_offset": "0x3920",
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
  "00013924": {
    "elf_va": "0x3924",
    "file_offset": "0x3924",
    "raw_u32": "0x4e94",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4e94",
    "target_string": "BIOS Flashing is Failed !!"
  },
  "00013928": {
    "elf_va": "0x3928",
    "file_offset": "0x3928",
    "raw_u32": "0x4eb0",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4eb0",
    "target_string": "Bios START update done FlashOffset %d: SizeToWrite %d\n"
  },
  "0001392c": {
    "elf_va": "0x392c",
    "file_offset": "0x392c",
    "raw_u32": "0x4650",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4650",
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
  iVar3 = sigwrap_open(DAT_00013910,2);
  __th = pthread_self();
  puVar1 = DAT_00013914;
  if (iVar3 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_0001392c,DAT_00013910);
    *DAT_00013914 = 0xffffffff;
    ActiveHostSPIDriver(1);
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_0001391c,DAT_00013918,local_30,local_2c);
  iVar4 = flash_bios_image(iVar3,DAT_00013920,local_30,local_2c,puVar1);
  if (iVar4 != 0) {
    ActiveHostSPIDriver(1);
    uVar2 = DAT_00013924;
    *puVar1 = 0xffffffff;
    IDBG_LINUXAPP_DbgOut(0x86,uVar2);
    sigwrap_close(iVar3);
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  sigwrap_close(iVar3);
  uVar2 = DAT_00013928;
  *puVar1 = 100;
  IDBG_LINUXAPP_DbgOut(0x86,uVar2,local_30,local_2c);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

