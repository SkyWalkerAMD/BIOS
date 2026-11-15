
undefined4
FUN_180003520(longlong param_1,ulonglong param_2,uint param_3,uint *param_4,void *param_5)

{
  HANDLE hFile;
  BOOL BVar1;
  undefined4 uVar2;
  void *lpBuffer;
  uint nNumberOfBytesToRead;
  uint local_res18 [2];
  
  uVar2 = 0;
  *param_4 = 0;
  if (*(uint *)(param_1 + 0x11c) < param_3) {
    return 0xffffffff;
  }
  hFile = *(HANDLE *)(param_1 + 0x108);
  nNumberOfBytesToRead = *(uint *)(param_1 + 0x118) * param_3;
  BVar1 = SetFilePointerEx(hFile,(LARGE_INTEGER)
                                 ((ulonglong)*(uint *)(param_1 + 0x118) * (param_2 & 0xffffffff)),
                           (PLARGE_INTEGER)0x0,0);
  if (BVar1 != -1) {
    lpBuffer = malloc((ulonglong)nNumberOfBytesToRead);
    if (lpBuffer == (void *)0x0) {
      uVar2 = 0xfffffffa;
    }
    else {
      BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,local_res18,(LPOVERLAPPED)0x0);
      if (local_res18[0] == nNumberOfBytesToRead) {
        *param_4 = nNumberOfBytesToRead;
        memcpy(param_5,lpBuffer,(ulonglong)nNumberOfBytesToRead);
      }
      else {
        uVar2 = 0xfffffffc;
        if (BVar1 == 0) {
          uVar2 = 0xffffffff;
        }
      }
      free(lpBuffer);
    }
    return uVar2;
  }
  return 0xffffffff;
}

