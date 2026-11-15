
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

