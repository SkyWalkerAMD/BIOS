
undefined4 FUN_00017d68(undefined4 param_1)

{
  int __fd;
  undefined4 uVar1;
  int *piVar2;
  char *pcVar3;
  int __errnum;
  
  __fd = sigwrap_open(DAT_00017dfc,DAT_00017df8);
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017e08,DAT_00017e04,0xe7);
    piVar2 = __errno_location();
    __errnum = *piVar2;
    pcVar3 = strerror(__errnum);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017e0c,DAT_00017e04,0xe8,__errnum,pcVar3);
    sigwrap_close(__fd);
    uVar1 = 0xffffffff;
  }
  else {
    ioctl(__fd,DAT_00017e00,param_1);
    sigwrap_close(__fd);
    uVar1 = 0;
  }
  return uVar1;
}

