
void do_bios_recovery(void)

{
  int iVar1;
  pthread_t __th;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined4 local_d4;
  undefined1 auStack_d0 [44];
  int local_a4;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  char local_64 [64];
  undefined4 local_24;
  
  iVar2 = DAT_0001223c;
  local_24 = **(undefined4 **)(DAT_00012234 + 0x1206c + DAT_00012238);
  local_64[0] = '\0';
  local_64[1] = '\0';
  local_64[2] = '\0';
  local_64[3] = '\0';
  memset(local_64 + 4,0,0x3c);
  local_74 = 0;
  local_70 = 0;
  local_6c = 0;
  local_68 = 0;
  local_d4 = 0;
  puVar4 = (undefined4 *)(DAT_00012244 + 0x120d8);
  snprintf(local_64,0x40,(char *)(DAT_00012248 + 0x120e0),
           *(undefined4 *)(*(int *)(iVar2 + 0x120a4 + DAT_00012240) + 0x15c));
  *puVar4 = 2;
  iVar1 = FUN_00014434(local_64,auStack_d0);
  __th = pthread_self();
  if (iVar1 == 0) {
    if (local_a4 == 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012258 + 0x12160,DAT_00012254 + 0x1215c,0x540);
      goto LAB_00012124;
    }
    uVar5 = *(undefined4 *)(iVar2 + 0x120a4 + DAT_0001225c);
    iVar2 = asus_find_bios_spi_device(uVar5);
    if (iVar2 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012264 + 0x12198,DAT_00012260 + 0x12194,0x548);
      *puVar4 = 0;
LAB_0001219c:
      pthread_detach(__th);
      goto LAB_00012134;
    }
    iVar2 = sigwrap_open(uVar5,2);
    if (iVar2 == -1) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00012268 + 0x121d4,uVar5);
      goto LAB_00012124;
    }
    iVar3 = flash_bios_image(iVar2,local_64,0,local_a4,&local_d4,&local_74);
    iVar1 = DAT_00012270;
    iVar2 = DAT_0001226c;
    if (iVar3 == 0) {
      *puVar4 = 1;
      IDBG_LINUXAPP_DbgOut(0x86,iVar1 + 0x12230);
      goto LAB_0001219c;
    }
    *puVar4 = 0;
    IDBG_LINUXAPP_DbgOut(0x86,iVar2 + 0x12214);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00012250 + 0x12124,DAT_0001224c + 0x1211c,0x538,local_64);
LAB_00012124:
    *puVar4 = 0;
  }
  pthread_detach(__th);
LAB_00012134:
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

