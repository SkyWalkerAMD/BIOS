
undefined4 FUN_180003620(longlong param_1,ulonglong param_2,uint param_3,void *param_4)

{
  HANDLE hFile;
  BOOL BVar1;
  undefined4 uVar2;
  void *_Dst;
  uint nNumberOfBytesToWrite;
  DWORD local_res18 [4];
  
  if (*(uint *)(param_1 + 0x11c) < param_3) {
    return 0xffffffff;
  }
  hFile = *(HANDLE *)(param_1 + 0x108);
  nNumberOfBytesToWrite = *(uint *)(param_1 + 0x118) * param_3;
  BVar1 = SetFilePointerEx(hFile,(LARGE_INTEGER)
                                 ((ulonglong)*(uint *)(param_1 + 0x118) * (param_2 & 0xffffffff)),
                           (PLARGE_INTEGER)0x0,0);
  if (BVar1 == -1) {
    return 0xffffffff;
  }
  _Dst = malloc((ulonglong)nNumberOfBytesToWrite);
  if (_Dst == (void *)0x0) {
    uVar2 = 0xfffffffa;
  }
  else {
    memcpy(_Dst,param_4,(ulonglong)nNumberOfBytesToWrite);
    WriteFile(hFile,_Dst,nNumberOfBytesToWrite,local_res18,(LPOVERLAPPED)0x0);
    free(_Dst);
    uVar2 = 0;
  }
  return uVar2;
}

