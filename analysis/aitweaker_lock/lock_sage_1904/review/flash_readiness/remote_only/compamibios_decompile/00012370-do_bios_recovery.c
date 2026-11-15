
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

