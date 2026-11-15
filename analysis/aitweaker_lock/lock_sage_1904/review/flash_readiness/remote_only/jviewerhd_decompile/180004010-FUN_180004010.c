
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

int FUN_180004010(char *param_1,int param_2)

{
  char cVar1;
  DWORD DVar2;
  UINT UVar3;
  UINT UVar4;
  int iVar5;
  BOOL BVar6;
  int iVar7;
  HANDLE hDevice;
  void *_Memory;
  char *pcVar8;
  uint uVar9;
  longlong lVar10;
  ulonglong uVar11;
  longlong lVar12;
  char *pcVar13;
  uint uVar14;
  longlong lVar15;
  bool bVar16;
  undefined1 auStackY_5e8 [32];
  DWORD local_5a0 [2];
  undefined1 local_598 [4];
  uint local_594;
  int local_590;
  char local_588 [32];
  undefined8 local_568;
  char local_168 [304];
  ulonglong local_38;
  
  local_38 = DAT_1800181d0 ^ (ulonglong)auStackY_5e8;
  FUN_180004f80(&local_568,0,0x400);
  DVar2 = GetLogicalDrives();
  uVar9 = 1;
  uVar14 = 0x41;
  lVar15 = 0x20;
  do {
    if ((DVar2 & uVar9) != 0) {
      sprintf(&DAT_1800195e8,"%c:\\",(ulonglong)uVar14);
      UVar3 = GetDriveTypeA(&DAT_1800195e8);
      UVar4 = GetDriveTypeA(&DAT_1800195e8);
      if ((1 < UVar4) && (UVar4 < 4)) {
        sprintf(local_168,"\\\\.\\%c:",(ulonglong)uVar14);
        hDevice = CreateFileA(local_168,0,0,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
        GetLastError();
        if (hDevice != (HANDLE)0xffffffffffffffff) {
          _Memory = (void *)FUN_18000506c(0x227);
          *(undefined4 *)((longlong)_Memory + 4) = 0x227;
          iVar5 = FUN_180003f90(hDevice,_Memory);
          if (iVar5 != 0) {
            if (*(int *)((longlong)_Memory + 0x1c) == 7) {
              bVar16 = param_2 == 1;
            }
            else {
              bVar16 = param_2 == 2;
            }
            if ((((bVar16) &&
                 (BVar6 = DeviceIoControl(hDevice,0x2d1080,(LPVOID)0x0,0,local_598,0xc,local_5a0,
                                          (LPOVERLAPPED)0x0), BVar6 != 0)) && (local_590 != -1)) &&
               (local_590 != 0)) {
              uVar11 = (ulonglong)local_594;
              lVar10 = uVar11 * 0x20;
              *(char *)((longlong)&local_568 + lVar10 + 1) = (char)UVar3 + '0';
              iVar5 = local_590;
              iVar7 = FUN_180003ff0((ulonglong)uVar9);
              *(char *)((longlong)&local_568 + (ulonglong)(iVar5 + 1) + lVar10) = (char)iVar7;
              *(char *)((longlong)&local_568 + lVar10) = (char)uVar11 + '0';
            }
          }
          free(_Memory);
          CloseHandle(hDevice);
        }
      }
    }
    uVar14 = uVar14 + 1;
    uVar9 = uVar9 << 1 | (uint)((int)uVar9 < 0);
    lVar15 = lVar15 + -1;
  } while (lVar15 != 0);
  lVar15 = 0x20;
  iVar5 = 0;
  pcVar13 = (char *)&local_568;
  do {
    iVar7 = iVar5;
    if (*pcVar13 != '\0') {
      iVar7 = 0;
      lVar12 = 0x20;
      pcVar8 = pcVar13;
      lVar10 = 0;
      do {
        if (*pcVar8 != '\0') {
          local_588[lVar10] = *pcVar8;
          iVar7 = iVar7 + 1;
          lVar10 = lVar10 + 1;
        }
        pcVar8 = pcVar8 + 1;
        lVar12 = lVar12 + -1;
      } while (lVar12 != 0);
      local_588[lVar10] = '\0';
      pcVar8 = local_588;
      do {
        cVar1 = *pcVar8;
        pcVar8 = pcVar8 + 1;
        pcVar8[(longlong)(param_1 + (-1 - (longlong)local_588))] = cVar1;
      } while (cVar1 != '\0');
      param_1 = param_1 + (iVar7 + 1);
      lVar12 = 2;
      iVar7 = iVar5 + 1;
      if (2 < lVar10) {
        do {
          cVar1 = local_588[lVar12];
          lVar12 = lVar12 + 1;
          *param_1 = local_588[0];
          param_1[1] = local_588[1];
          param_1[3] = 'l';
          param_1[4] = '\0';
          param_1[2] = cVar1;
          param_1 = param_1 + 5;
          iVar7 = iVar5 + -1 + (int)lVar10;
        } while (lVar12 < lVar10);
      }
    }
    iVar5 = iVar7;
    pcVar13 = pcVar13 + 0x20;
    lVar15 = lVar15 + -1;
  } while (lVar15 != 0);
  return iVar5;
}

