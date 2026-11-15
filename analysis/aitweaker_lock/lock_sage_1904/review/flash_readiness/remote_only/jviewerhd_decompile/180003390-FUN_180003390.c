
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_180003390(LPCSTR param_1)

{
  HANDLE pvVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined1 auStackY_258 [32];
  WCHAR local_218 [256];
  ulonglong local_18;
  
  local_18 = DAT_1800181d0 ^ (ulonglong)auStackY_258;
  if (param_1[0x122] == '\x01') {
    if (*(longlong *)(param_1 + 0x108) != 0) {
      return 0xfffffff3;
    }
  }
  else if (*(longlong *)(param_1 + 0x108) != 0) {
    return 0;
  }
  MultiByteToWideChar(0xfde9,0,param_1,-1,local_218,0x100);
  uVar3 = 0;
  uVar2 = 0;
  pvVar1 = CreateFileW(local_218,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (pvVar1 != (HANDLE)0xffffffffffffffff) {
    *(longlong *)(param_1 + 0x108) = (longlong)(int)pvVar1;
    return 0;
  }
  FUN_180004400("Unable to open image file - %s\n",param_1,uVar2,uVar3);
  return 0xfffffffb;
}

