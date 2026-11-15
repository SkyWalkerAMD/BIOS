/* ELF literal/relocation annotations (Ghidra bias 0x10000).
{
  "000131b8": {
    "elf_va": "0x31b8",
    "file_offset": "0x31b8",
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
  "000131bc": {
    "elf_va": "0x31bc",
    "file_offset": "0x31bc",
    "raw_u32": "0x4a88",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4a88",
    "target_string": "[%s:%d]ActiveHostSPIDriver(%d)\n"
  },
  "000131c0": {
    "elf_va": "0x31c0",
    "file_offset": "0x31c0",
    "raw_u32": "0x4aa8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4aa8",
    "target_string": "/sbin/rmmod host_spi_flash_hw"
  },
  "000131c4": {
    "elf_va": "0x31c4",
    "file_offset": "0x31c4",
    "raw_u32": "0x4adc",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4adc",
    "target_string": "/sbin/insmod /lib/modules/generic/misc/host_spi_flash_hw.ko"
  },
  "000131c8": {
    "elf_va": "0x31c8",
    "file_offset": "0x31c8",
    "raw_u32": "0x4ac8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4ac8",
    "target_string": "rm /var/rom_id.tmp"
  },
  "000131cc": {
    "elf_va": "0x31cc",
    "file_offset": "0x31cc",
    "raw_u32": "0x4b18",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b18",
    "target_string": "r"
  },
  "000131d0": {
    "elf_va": "0x31d0",
    "file_offset": "0x31d0",
    "raw_u32": "0x4b1c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b1c",
    "target_string": "/var/rom_id.tmp"
  },
  "000131d4": {
    "elf_va": "0x31d4",
    "file_offset": "0x31d4",
    "raw_u32": "0x4b2c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b2c",
    "target_string": "[SPI] spi=1.8v,rom id = 0x%s\n"
  },
  "000131d8": {
    "elf_va": "0x31d8",
    "file_offset": "0x31d8",
    "raw_u32": "0x4b4c",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b4c",
    "target_string": "00FFFFFF"
  },
  "000131dc": {
    "elf_va": "0x31dc",
    "file_offset": "0x31dc",
    "raw_u32": "0x16454",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x16454"
  },
  "000131e0": {
    "elf_va": "0x31e0",
    "file_offset": "0x31e0",
    "raw_u32": "0x40533333",
    "target_elf_va": "0x40533333"
  },
  "000131e4": {
    "elf_va": "0x31e4",
    "file_offset": "0x31e4",
    "raw_u32": "0x4bd8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4bd8",
    "target_string": "[SPI] switch to 3.3v by rom id table\n"
  },
  "000131e8": {
    "elf_va": "0x31e8",
    "file_offset": "0x31e8",
    "raw_u32": "0x4ba8",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4ba8",
    "target_string": "[SPI] spi=1.8v, File /var/rom_id.tmp not found\n"
  },
  "000131ec": {
    "elf_va": "0x31ec",
    "file_offset": "0x31ec",
    "raw_u32": "0x4b58",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b58",
    "target_string": "[SPI] spi=3.3v,rom id = 0x%s\n"
  },
  "000131f0": {
    "elf_va": "0x31f0",
    "file_offset": "0x31f0",
    "raw_u32": "0x4b78",
    "relocation": {
      "type": 23,
      "symbol": "",
      "symbol_va": 0,
      "symbol_defined": false
    },
    "target_elf_va": "0x4b78",
    "target_string": "[SPI] spi=3.3v, File /var/rom_id.tmp not found\n"
  }
}
*/

undefined4 ActiveHostSPIDriver(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  FILE *__stream;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  char local_a4 [12];
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  
  memset(&local_98,0,0x80);
  local_a4[0] = '\0';
  local_a4[1] = '\0';
  local_a4[2] = '\0';
  local_a4[3] = '\0';
  local_a4[4] = '\0';
  local_a4[5] = '\0';
  local_a4[6] = '\0';
  local_a4[7] = '\0';
  local_a4[8] = 0;
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000131bc,DAT_000131b8,0xdc,param_1);
  puVar2 = DAT_000131c4;
  puVar1 = DAT_000131c0;
  if (param_1 != 0) {
    local_98 = *DAT_000131c0;
    uStack_94 = DAT_000131c0[1];
    uStack_90 = DAT_000131c0[2];
    uStack_8c = DAT_000131c0[3];
    local_88 = DAT_000131c0[4];
    uStack_84 = DAT_000131c0[5];
    uStack_80 = DAT_000131c0[6];
    local_7c = CONCAT22(local_7c._2_2_,(short)DAT_000131c0[7]);
    safe_system(&local_98);
    SwitchGPIO(1);
    ClearASUSBiosHeader();
    return 0;
  }
  local_98 = *DAT_000131c0;
  uStack_94 = DAT_000131c0[1];
  uStack_90 = DAT_000131c0[2];
  uStack_8c = DAT_000131c0[3];
  puVar7 = DAT_000131c0 + 4;
  local_88 = *puVar7;
  uStack_84 = DAT_000131c0[5];
  uStack_80 = DAT_000131c0[6];
  local_7c = CONCAT22(local_7c._2_2_,(short)DAT_000131c0[7]);
  safe_system(&local_98);
  sleep(2);
  SwitchGPIO(0);
  sleep(1);
  safe_system(DAT_000131c8);
  local_98 = *puVar2;
  uStack_94 = puVar2[1];
  uStack_90 = puVar2[2];
  uStack_8c = puVar2[3];
  local_88 = puVar2[4];
  uStack_84 = puVar2[5];
  uStack_80 = puVar2[6];
  local_7c = puVar2[7];
  local_78 = puVar2[8];
  uStack_74 = puVar2[9];
  uStack_70 = puVar2[10];
  uStack_6c = puVar2[0xb];
  local_68 = puVar2[0xc];
  uStack_64 = puVar2[0xd];
  uStack_60 = puVar2[0xe];
  safe_system(&local_98);
  sleep(2);
  __stream = fopen(DAT_000131d0,DAT_000131cc);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000131e8);
  }
  else {
    fread(local_a4,1,9,__stream);
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000131d4,local_a4);
    iVar3 = strncmp(local_a4,DAT_000131d8,8);
    if (iVar3 != 0) {
      iVar3 = 1;
      goto LAB_00012fdc;
    }
    fclose(__stream);
    safe_system(DAT_000131c8);
  }
  local_98 = *puVar1;
  uStack_94 = puVar1[1];
  uStack_90 = puVar1[2];
  uStack_8c = puVar1[3];
  local_88 = *puVar7;
  uStack_84 = puVar1[5];
  uStack_80 = puVar1[6];
  local_7c = CONCAT22(local_7c._2_2_,(short)puVar1[7]);
  safe_system(&local_98);
  sleep(2);
  SwitchGPIO(2);
  local_98 = *puVar2;
  uStack_94 = puVar2[1];
  uStack_90 = puVar2[2];
  uStack_8c = puVar2[3];
  local_88 = puVar2[4];
  uStack_84 = puVar2[5];
  uStack_80 = puVar2[6];
  local_7c = puVar2[7];
  local_78 = puVar2[8];
  uStack_74 = puVar2[9];
  uStack_70 = puVar2[10];
  uStack_6c = puVar2[0xb];
  local_68 = puVar2[0xc];
  uStack_64 = puVar2[0xd];
  uStack_60 = puVar2[0xe];
  safe_system(&local_98);
  sleep(2);
  __stream = fopen(DAT_000131d0,DAT_000131cc);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000131f0);
    return 0;
  }
  fread(local_a4,1,9,__stream);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_000131ec,local_a4);
  iVar3 = 2;
LAB_00012fdc:
  iVar5 = DAT_000131dc;
  fclose(__stream);
  iVar6 = iVar5 + 0x48;
  do {
    pcVar4 = strstr(local_a4,*(char **)(iVar5 + 4));
    if (pcVar4 != (char *)0x0) {
      iVar5 = FUN_00014330(*(undefined4 *)(iVar5 + 8),DAT_000131e0);
      if (iVar5 == 0 || iVar3 == 2) {
        return 0;
      }
      local_98 = *DAT_000131c0;
      uStack_94 = DAT_000131c0[1];
      uStack_90 = DAT_000131c0[2];
      uStack_8c = DAT_000131c0[3];
      local_88 = DAT_000131c0[4];
      uStack_84 = DAT_000131c0[5];
      uStack_80 = DAT_000131c0[6];
      local_7c = CONCAT22(local_7c._2_2_,(short)DAT_000131c0[7]);
      safe_system(&local_98);
      sleep(2);
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000131e4);
      SwitchGPIO(2);
      local_98 = *DAT_000131c4;
      uStack_94 = DAT_000131c4[1];
      uStack_90 = DAT_000131c4[2];
      uStack_8c = DAT_000131c4[3];
      local_88 = DAT_000131c4[4];
      uStack_84 = DAT_000131c4[5];
      uStack_80 = DAT_000131c4[6];
      local_7c = DAT_000131c4[7];
      local_78 = DAT_000131c4[8];
      uStack_74 = DAT_000131c4[9];
      uStack_70 = DAT_000131c4[10];
      uStack_6c = DAT_000131c4[0xb];
      local_68 = DAT_000131c4[0xc];
      uStack_64 = DAT_000131c4[0xd];
      uStack_60 = DAT_000131c4[0xe];
      safe_system(&local_98);
      sleep(2);
      return 0;
    }
    iVar5 = iVar5 + 0xc;
  } while (iVar6 != iVar5);
  return 0;
}

