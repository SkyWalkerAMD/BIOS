
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined8 FUN_180002f70(longlong param_1,uint *param_2,undefined4 *param_3)

{
  DWORD DVar1;
  BOOL BVar2;
  int iVar3;
  undefined1 *lpBuffer;
  undefined8 uVar4;
  undefined8 uVar5;
  LPDWORD lpNumberOfBytesRead;
  undefined1 auStackY_2a8 [32];
  DWORD local_268;
  DWORD local_264;
  undefined1 local_260 [20];
  uint local_24c;
  undefined1 local_248 [8];
  longlong local_240;
  undefined1 local_228 [512];
  ulonglong local_28;
  
  local_28 = DAT_1800181d0 ^ (ulonglong)auStackY_2a8;
  lpNumberOfBytesRead = (LPDWORD)0x0;
  uVar5 = 0;
  lpBuffer = (undefined1 *)0x0;
  DVar1 = SetFilePointer(*(HANDLE *)(param_1 + 0x28),0,(PLONG)0x0,0);
  if (DVar1 != 0xffffffff) {
    lpNumberOfBytesRead = &local_264;
    lpBuffer = local_228;
    uVar5 = 0x200;
    BVar2 = ReadFile(*(HANDLE *)(param_1 + 0x28),lpBuffer,0x200,lpNumberOfBytesRead,
                     (LPOVERLAPPED)0x0);
    if (BVar2 != 0) {
      lpNumberOfBytesRead = (LPDWORD)0x0;
      uVar5 = 0;
      lpBuffer = (undefined1 *)0x70000;
      BVar2 = DeviceIoControl(*(HANDLE *)(param_1 + 0x28),0x70000,(LPVOID)0x0,0,local_260,0x18,
                              &local_268,(LPOVERLAPPED)0x0);
      if (BVar2 != 0) {
        *param_2 = local_24c;
        BVar2 = DeviceIoControl(*(HANDLE *)(param_1 + 0x28),0x74004,(LPVOID)0x0,0,local_248,0x20,
                                &local_268,(LPOVERLAPPED)0x0);
        if (BVar2 != 0) {
          *param_3 = (int)(local_240 / (longlong)(ulonglong)local_24c);
        }
        return 0;
      }
    }
  }
  *param_2 = 0;
  *param_3 = 0;
  DVar1 = GetLastError();
  if ((DVar1 == 0x456) || (DVar1 == 0x22)) {
    uVar4 = 0xfffffffd;
    FUN_1800025c0(param_1);
    iVar3 = FUN_180002250(param_1);
    if (iVar3 != 0) {
      FUN_180004460("Medium changed, unable to open the new media. returning media error",lpBuffer,
                    uVar5,lpNumberOfBytesRead);
      uVar4 = 0xfffffffc;
    }
  }
  else {
    uVar4 = 0xfffffffb;
  }
  return uVar4;
}

