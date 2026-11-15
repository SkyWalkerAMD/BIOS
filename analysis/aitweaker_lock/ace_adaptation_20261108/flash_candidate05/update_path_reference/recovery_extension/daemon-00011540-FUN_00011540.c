/* Exact ELF literal/relocation map. */
{
  "00011608": {
    "elf_va": "0x11608",
    "file_offset": "0x1608",
    "raw_u32": "0x1000c",
    "target_elf_va": "0x1000c"
  },
  "0001160c": {
    "elf_va": "0x1160c",
    "file_offset": "0x160c",
    "raw_u32": "0x11f94",
    "target_elf_va": "0x11f94",
    "target_string": "compmanager.c"
  },
  "00011610": {
    "elf_va": "0x11610",
    "file_offset": "0x1610",
    "raw_u32": "0x12040",
    "target_elf_va": "0x12040",
    "target_string": "[%s:%d]Error in Activating the Component ID = %d \n"
  }
}

void FUN_00011540(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined1 auStack_10024 [4];
  int iStack_10020;
  
  memset(auStack_10024,0,DAT_00011608);
  iVar3 = get_deferred_activate_all();
  uVar2 = DAT_00011610;
  uVar1 = DAT_0001160c;
  if (iVar3 != 1) {
    return;
  }
  uVar4 = 0;
  do {
    while (iVar3 = get_deferred_activation_configs(uVar4), iVar3 == 1) {
      CMD_Activate_Firmware_Image(auStack_10024,uVar4 & 0xff,1);
      if (iStack_10020 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,uVar2,uVar1,0x5d,uVar4);
      }
      uVar5 = uVar4 + 1;
      set_deferred_activation_configs(uVar4,0);
      uVar4 = uVar5;
      if (uVar5 == 8) goto LAB_00010e48;
    }
    uVar4 = uVar4 + 1;
  } while (uVar4 != 8);
LAB_00010e48:
  (*(code *)PTR_set_deferred_activate_all_0002305c)(0);
  return;
}

