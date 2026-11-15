
ulonglong FUN_1800020f0(longlong *param_1,ulonglong param_2,int param_3,void *param_4)

{
  uint uVar1;
  DWORD DVar2;
  BOOL BVar3;
  ulonglong uVar4;
  LPVOID _Dst;
  uint uVar5;
  uint nNumberOfBytesToWrite;
  uint local_res10 [2];
  DWORD local_res18 [2];
  
  uVar5 = (uint)param_2;
  local_res18[0] = 0;
  local_res10[0] = 0;
  if ((*(int *)((longlong)param_1 + 0x1c) != 0) ||
     (uVar4 = (**(code **)(*param_1 + 0x38))(), (int)uVar4 == 0)) {
    uVar1 = 0;
    if (param_3 == 0) {
      return 0;
    }
    nNumberOfBytesToWrite = param_3 * *(int *)((longlong)param_1 + 0x1c);
    _Dst = VirtualAlloc((LPVOID)0x0,(ulonglong)nNumberOfBytesToWrite,0x3000,4);
    if (_Dst == (LPVOID)0x0) {
      uVar1 = 0xfffffffa;
    }
    else {
      memcpy(_Dst,param_4,(ulonglong)nNumberOfBytesToWrite);
      if (0x7fffff < uVar5) {
        local_res10[0] = (uint)(param_2 >> 0x17) & 0x1ff;
        uVar5 = uVar5 & 0x7fffff;
      }
      DVar2 = SetFilePointer((HANDLE)param_1[5],uVar5 * *(int *)((longlong)param_1 + 0x1c),
                             (PLONG)local_res10,0);
      if (DVar2 == 0xffffffff) {
        uVar1 = 0xffffffff;
      }
      else {
        BVar3 = WriteFile((HANDLE)param_1[5],_Dst,nNumberOfBytesToWrite,local_res18,
                          (LPOVERLAPPED)0x0);
        if (BVar3 == 0) {
          if (local_res18[0] == 0) {
            DVar2 = GetLastError();
            uVar1 = 0xffffffff;
            if (DVar2 == 0x13) {
              uVar1 = 0xfffffff3;
            }
          }
          else {
            uVar1 = 0xfffffffc;
          }
        }
      }
      VirtualFree(_Dst,0,0x8000);
    }
    uVar4 = (ulonglong)uVar1;
  }
  return uVar4;
}

