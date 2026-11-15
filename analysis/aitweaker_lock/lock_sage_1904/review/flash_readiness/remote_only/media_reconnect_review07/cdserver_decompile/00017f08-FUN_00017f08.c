
uint FUN_00017f08(ulong param_1,undefined4 param_2)

{
  int __fd;
  uint uVar1;
  int *piVar2;
  char *pcVar3;
  int __errnum;
  
  __fd = sigwrap_open(DAT_00017fa0,DAT_00017fa4);
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017fb0,DAT_00017fac,DAT_00017fa8);
    piVar2 = __errno_location();
    __errnum = *piVar2;
    pcVar3 = strerror(__errnum);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017fb8,DAT_00017fac,DAT_00017fb4,__errnum,pcVar3);
    sigwrap_close(__fd);
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = ioctl(__fd,param_1,param_2);
    sigwrap_close(__fd);
    uVar1 = uVar1 & 0xff;
  }
  return uVar1;
}

