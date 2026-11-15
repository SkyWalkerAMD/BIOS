
undefined4 FUN_00017c98(int param_1)

{
  int __fd;
  undefined4 uVar1;
  int *piVar2;
  char *pcVar3;
  int __errnum;
  
  __fd = sigwrap_open(DAT_00017d50,DAT_00017d4c);
  if (__fd < 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017d60,DAT_00017d5c,0xd3);
    piVar2 = __errno_location();
    __errnum = *piVar2;
    pcVar3 = strerror(__errnum);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017d64,DAT_00017d5c,0xd4,__errnum,pcVar3);
    sigwrap_close(__fd);
    uVar1 = 0xffffffff;
  }
  else {
    if (param_1 == 1) {
      ioctl(__fd,DAT_00017d58,0);
    }
    else if (param_1 == 0) {
      ioctl(__fd,DAT_00017d54,0);
    }
    sigwrap_close(__fd);
    uVar1 = 0;
  }
  return uVar1;
}

