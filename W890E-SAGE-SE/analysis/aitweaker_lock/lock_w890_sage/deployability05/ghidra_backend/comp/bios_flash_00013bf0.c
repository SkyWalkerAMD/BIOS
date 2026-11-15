
void bios_flash(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  pthread_t __th;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined4 local_74 [8];
  uint local_54 [4];
  char local_44 [32];
  undefined4 local_24;
  
  local_24 = **(undefined4 **)(DAT_00013d74 + 0x13c04 + DAT_00013d78);
  local_44[0] = '\0';
  local_44[1] = '\0';
  local_44[2] = '\0';
  local_44[3] = '\0';
  memset(local_44 + 4,0,0x1c);
  local_54[0] = 0;
  local_54[1] = 0;
  local_54[2] = 0;
  local_54[3] = 0;
  Getpdklib(1);
  puVar5 = local_74;
  puVar7 = param_1 + 8;
  iVar6 = DAT_00013d7c + 0x13c60;
  do {
    uVar1 = *param_1;
    uVar4 = param_1[1];
    param_1 = param_1 + 2;
    *puVar5 = uVar1;
    puVar5[1] = uVar4;
    puVar5 = puVar5 + 2;
  } while (param_1 != puVar7);
  local_54[0] = local_54[0] & 0xffffff00;
  strcpy(local_44,(char *)(DAT_00013d80 + 0x13c94));
  uVar1 = *(undefined4 *)(iVar6 + DAT_00013d84);
  iVar2 = sigwrap_open(uVar1,2);
  puVar5 = *(undefined4 **)(iVar6 + DAT_00013d88);
  if (iVar2 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013d8c + 0x13cdc,uVar1);
    *puVar5 = 0xffffffff;
    ActiveHostSPIDriver(1);
  }
  else {
    iVar3 = flash_bios_image(iVar2,local_44,local_74[0],local_74[1],puVar5,local_54);
    iVar6 = DAT_00013d90;
    if (iVar3 == 0) {
      sigwrap_close(iVar2);
      iVar6 = DAT_00013d94;
      *puVar5 = 100;
      IDBG_LINUXAPP_DbgOut(0x86,iVar6 + 0x13d68,local_74[0],local_74[1]);
    }
    else {
      *puVar5 = 0xffffffff;
      IDBG_LINUXAPP_DbgOut(0x86,iVar6 + 0x13d3c);
      sigwrap_close(iVar2);
    }
  }
  Getpdklib(2);
  __th = pthread_self();
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

