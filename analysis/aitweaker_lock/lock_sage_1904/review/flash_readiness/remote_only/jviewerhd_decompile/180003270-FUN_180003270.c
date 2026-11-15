
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_180003270(LPCSTR param_1)

{
  DWORD DVar1;
  HANDLE pvVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined1 auStackY_258 [32];
  WCHAR local_218 [256];
  ulonglong local_18;
  
  local_18 = DAT_1800181d0 ^ (ulonglong)auStackY_258;
  MultiByteToWideChar(0xfde9,0,param_1,-1,local_218,0x100);
  pvVar2 = CreateFileW(local_218,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (pvVar2 == (HANDLE)0xffffffffffffffff) {
    DVar1 = GetLastError();
    if ((DVar1 != 5) && (DVar1 != 2)) {
      if (DVar1 != 0x20) {
        return 0xfffffffb;
      }
      return 0xfffffffd;
    }
    uVar4 = 0;
    uVar3 = 1;
    pvVar2 = CreateFileW(local_218,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (pvVar2 == (HANDLE)0xffffffffffffffff) {
      FUN_180004400("Unable to open image file - %s\n",param_1,uVar3,uVar4);
      return 0xfffffffb;
    }
    param_1[0x122] = '\x01';
  }
  *(longlong *)(param_1 + 0x108) = (longlong)(int)pvVar2;
  return 0;
}

