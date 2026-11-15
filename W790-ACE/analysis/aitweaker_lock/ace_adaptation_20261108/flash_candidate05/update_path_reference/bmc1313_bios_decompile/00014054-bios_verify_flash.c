
void bios_verify_flash(void *param_1)

{
  int iVar1;
  pthread_t __th;
  int iVar2;
  int iVar3;
  undefined4 local_a8;
  undefined4 local_a4;
  char acStack_98 [64];
  char acStack_58 [64];
  
  memset(acStack_98,0,0x40);
  memset(acStack_58,0,0x40);
  memcpy(&local_a8,param_1,0x10);
  snprintf(acStack_98,0x40,DAT_000141f4,*(undefined4 *)(DAT_000141f0 + 0x160));
  iVar1 = sigwrap_open(DAT_000141f8,2);
  __th = pthread_self();
  iVar3 = DAT_000141fc;
  if (iVar1 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014214,DAT_000141f8);
    ActiveHostSPIDriver(1);
    *(undefined4 *)(DAT_000141fc + 4) = 0xffffffff;
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014204,DAT_00014200,local_a8,local_a4);
  iVar2 = verify_bios_img(iVar1,local_a8,local_a4,iVar3 + 4);
  if (iVar2 == 0) {
    sigwrap_close(iVar1);
    ActiveHostSPIDriver(1);
    if ((*(int *)(iVar3 + 4) == -1) || (*(int *)(DAT_00014208 + 0x34c) != 1)) {
      unlink(DAT_0001420c);
    }
    else {
      snprintf(acStack_58,0x40,DAT_00014218,DAT_0001420c,acStack_98);
      iVar3 = safe_system(acStack_58);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_0001421c);
      }
    }
    write_forcedUpdate_flag();
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014210);
  ActiveHostSPIDriver(1);
  *(undefined4 *)(iVar3 + 4) = 0xffffffff;
  sigwrap_close(iVar1);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

