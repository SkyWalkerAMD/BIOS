
undefined8
FUN_180001fc0(longlong *param_1,ulonglong param_2,int param_3,uint *param_4,void *param_5)

{
  DWORD DVar1;
  BOOL BVar2;
  undefined8 uVar3;
  LPVOID lpBuffer;
  uint uVar4;
  uint nNumberOfBytesToRead;
  uint local_res8 [2];
  uint local_res20 [2];
  
  *param_4 = 0;
  uVar4 = (uint)param_2;
  local_res8[0] = 0;
  if ((*(int *)((longlong)param_1 + 0x1c) != 0) ||
     (uVar3 = (**(code **)(*param_1 + 0x38))(), (int)uVar3 == 0)) {
    if (param_3 == 0) {
      return 0;
    }
    nNumberOfBytesToRead = *(int *)((longlong)param_1 + 0x1c) * param_3;
    lpBuffer = VirtualAlloc((LPVOID)0x0,(ulonglong)nNumberOfBytesToRead,0x3000,4);
    if (lpBuffer == (LPVOID)0x0) {
      return 0xfffffffa;
    }
    if (0x7fffff < uVar4) {
      local_res8[0] = (uint)(param_2 >> 0x17) & 0x1ff;
      uVar4 = uVar4 & 0x7fffff;
    }
    DVar1 = SetFilePointer((HANDLE)param_1[5],*(int *)((longlong)param_1 + 0x1c) * uVar4,
                           (PLONG)local_res8,0);
    if (DVar1 == 0xffffffff) {
      uVar3 = 0xffffffff;
    }
    else {
      BVar2 = ReadFile((HANDLE)param_1[5],lpBuffer,nNumberOfBytesToRead,local_res20,
                       (LPOVERLAPPED)0x0);
      if (BVar2 == 0) {
        uVar3 = 0xfffffffc;
        if (local_res20[0] == 0) {
          uVar3 = 0xffffffff;
        }
      }
      else {
        *param_4 = local_res20[0];
        memcpy(param_5,lpBuffer,(ulonglong)local_res20[0]);
        uVar3 = 0;
      }
    }
    VirtualFree(lpBuffer,0,0x8000);
  }
  return uVar3;
}

