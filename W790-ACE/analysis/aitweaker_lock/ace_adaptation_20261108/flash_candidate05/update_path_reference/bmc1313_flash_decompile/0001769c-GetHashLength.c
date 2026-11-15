
int GetHashLength(int param_1)

{
  int __fd;
  __off_t _Var1;
  int iVar2;
  int local_18;
  uint local_14;
  
  if (param_1 == 0) {
    iVar2 = -1;
  }
  else {
    __fd = sigwrap_open(param_1,0);
    if (__fd == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000177b0,DAT_000177a4,DAT_000177ac);
      return -1;
    }
    _Var1 = lseek(__fd,-8,2);
    if (_Var1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000177b8,DAT_000177a4,DAT_000177b4);
      iVar2 = -1;
    }
    else {
      iVar2 = sigwrap_read(__fd,&local_18,8);
      if (iVar2 == 8) {
        iVar2 = 8;
        if (local_18 == DAT_0001779c) {
          iVar2 = ~(local_14 | 0xff000000) + 8;
          printf(DAT_000177bc,iVar2,~(local_14 | 0xff000000),8);
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000177a8,DAT_000177a4,DAT_000177a0);
        iVar2 = -1;
      }
    }
    sigwrap_close(__fd);
  }
  return iVar2;
}

