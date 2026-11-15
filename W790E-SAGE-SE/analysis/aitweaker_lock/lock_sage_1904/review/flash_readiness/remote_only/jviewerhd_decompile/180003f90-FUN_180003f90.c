
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

void FUN_180003f90(HANDLE param_1,LPVOID param_2)

{
  undefined1 auStackY_68 [32];
  DWORD local_28 [2];
  undefined8 local_20 [2];
  ulonglong local_10;
  
  local_10 = DAT_1800181d0 ^ (ulonglong)auStackY_68;
  local_20[0] = 0;
  DeviceIoControl(param_1,0x2d1400,local_20,0xc,param_2,*(DWORD *)((longlong)param_2 + 4),local_28,
                  (LPOVERLAPPED)0x0);
  return;
}

