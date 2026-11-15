
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_1800026e0(longlong param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  undefined1 auStackY_468 [32];
  DWORD local_428 [4];
  undefined1 local_418 [1024];
  ulonglong local_18;
  
  local_18 = DAT_1800181d0 ^ (ulonglong)auStackY_468;
  local_428[0] = 0;
  BVar1 = DeviceIoControl(*(HANDLE *)(param_1 + 0x28),0x70024,(LPVOID)0x0,0,local_418,0x400,
                          local_428,(LPOVERLAPPED)0x0);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    if (DVar2 == 0x13) {
      return 0xfffffff3;
    }
  }
  return 0;
}

