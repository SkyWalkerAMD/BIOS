

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
  iVar3 = sigwrap_open(&MTD_Device,2);
  __th = pthread_self();
  puVar1 = 0x164a0;
  if (iVar3 == -1) {
    IDBG_LINUXAPP_DbgOut(0x86,"ERROR: open failed (%s)\n",&MTD_Device);
    *0x164a0 = 0xffffffff;
    ActiveHostSPIDriver(1);
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  IDBG_LINUXAPP_DbgOut(0x86,"[%s] FlashOffset = 0x%x, Size = 0x%x\n","bios_flash",local_30,local_2c);
  iVar4 = flash_bios_image(iVar3,"/var/bios.bin",local_30,local_2c,puVar1);
  if (iVar4 != 0) {
    ActiveHostSPIDriver(1);
    uVar2 = "BIOS Flashing is Failed !!";
    *puVar1 = 0xffffffff;
    IDBG_LINUXAPP_DbgOut(0x86,uVar2);
    sigwrap_close(iVar3);
    pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
    pthread_exit((void *)0x0);
  }
  sigwrap_close(iVar3);
  uVar2 = "Bios START update done FlashOffset %d: SizeToWrite %d\n";
  *puVar1 = 100;
  IDBG_LINUXAPP_DbgOut(0x86,uVar2,local_30,local_2c);
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

