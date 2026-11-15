
void bios_verify_flash(void *param_1)

{
  int iVar1;
  pthread_t __th;
  int iVar2;
  int iVar3;
  undefined4 local_c0;
  undefined4 local_bc;
  char acStack_b0 [64];
  char acStack_70 [88];
  
  memset(acStack_b0,0,0x40);
  memset(acStack_70,0,0x58);
  memcpy(&local_c0,param_1,0x10);
  snprintf(acStack_b0,0x40,DAT_00014148,*(undefined4 *)(DAT_00014144 + 0x160));
  iVar1 = sigwrap_open(DAT_0001414c,2);
  __th = pthread_self();
  iVar3 = DAT_00014150;
  if (iVar1 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00014168,DAT_0001414c);
    ActiveHostSPIDriver(1);
    *(undefined4 *)(DAT_00014150 + 4) = 0xffffffff;
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014158,DAT_00014154,local_c0,local_bc);
  iVar2 = verify_bios_img(iVar1,local_c0,local_bc,iVar3 + 4);
  if (iVar2 == 0) {
    sigwrap_close(iVar1);
    ActiveHostSPIDriver(1);
    if ((*(int *)(iVar3 + 4) == -1) || (*(int *)(DAT_0001415c + 0x350) != 1)) {
      unlink(DAT_00014160);
    }
    else {
      snprintf(acStack_70,0x58,DAT_0001416c,DAT_00014160,acStack_b0);
      iVar3 = safe_system(acStack_70);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00014170);
      }
    }
    write_forcedUpdate_flag();
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014164);
  ActiveHostSPIDriver(1);
  *(undefined4 *)(iVar3 + 4) = 0xffffffff;
  sigwrap_close(iVar1);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

