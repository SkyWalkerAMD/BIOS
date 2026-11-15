
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

int FUN_180002250(longlong param_1)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  BOOL BVar4;
  DWORD DVar5;
  int iVar6;
  HANDLE pvVar7;
  int iVar8;
  longlong lVar9;
  undefined8 uVar10;
  char *pcVar11;
  int iVar12;
  char *pcVar13;
  undefined8 *puVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined1 auStackY_98 [32];
  DWORD local_54;
  char local_50 [32];
  ulonglong local_30;
  
  local_30 = DAT_1800181d0 ^ (ulonglong)auStackY_98;
  bVar2 = false;
  iVar6 = 0;
  bVar3 = FUN_180002230();
  lVar9 = -1;
  pcVar11 = (char *)(param_1 + 0x40);
  local_50[0] = '\0';
  local_50[1] = '\0';
  local_50[2] = '\0';
  local_50[3] = '\0';
  local_50[4] = '\0';
  local_50[5] = '\0';
  local_50[6] = '\0';
  local_50[7] = '\0';
  local_50[8] = '\0';
  local_50[9] = '\0';
  local_50[10] = '\0';
  local_50[0xb] = '\0';
  local_50[0xc] = '\0';
  local_50[0xd] = '\0';
  local_50[0xe] = '\0';
  local_50[0xf] = '\0';
  pcVar13 = pcVar11;
  do {
    if (lVar9 == 0) break;
    lVar9 = lVar9 + -1;
    cVar1 = *pcVar13;
    pcVar13 = pcVar13 + 1;
  } while (cVar1 != '\0');
  local_50[0x10] = '\0';
  local_50[0x11] = '\0';
  local_50[0x12] = '\0';
  local_50[0x13] = '\0';
  local_50[0x14] = '\0';
  local_50[0x15] = '\0';
  local_50[0x16] = '\0';
  local_50[0x17] = '\0';
  local_50[0x18] = '\0';
  local_50[0x19] = '\0';
  local_50[0x1a] = '\0';
  local_50[0x1b] = '\0';
  local_50[0x1c] = '\0';
  local_50[0x1d] = '\0';
  iVar12 = 0;
  iVar8 = ~(uint)lVar9 - 1;
  if (0 < iVar8) {
    puVar14 = (undefined8 *)(param_1 + 0x50);
    iVar12 = 0;
    do {
      sprintf(local_50,"\\\\.\\%c:");
      if (*pcVar11 != ' ') {
        if (bVar3) {
          DVar5 = 3;
        }
        else {
          DVar5 = 0;
        }
        pvVar7 = CreateFileA(local_50,0xc0000000,DVar5,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
        *puVar14 = pvVar7;
        if (pvVar7 != (HANDLE)0xffffffffffffffff) {
          uVar15 = 0;
          uVar10 = 0;
          BVar4 = DeviceIoControl(pvVar7,0x90018,(LPVOID)0x0,0,(LPVOID)0x0,0,&local_54,
                                  (LPOVERLAPPED)0x0);
          if (BVar4 == 0) {
            DVar5 = GetLastError();
            FUN_180004400("DeviceIoControl to lock drive failed with %u\n",(ulonglong)DVar5,uVar10,
                          uVar15);
          }
          else {
            BVar4 = DeviceIoControl((HANDLE)*puVar14,0x90020,(LPVOID)0x0,0,(LPVOID)0x0,0,&local_54,
                                    (LPOVERLAPPED)0x0);
            if (BVar4 != 0) goto LAB_1800023a5;
          }
        }
        bVar2 = true;
        break;
      }
LAB_1800023a5:
      pcVar11 = pcVar11 + 1;
      iVar12 = iVar12 + 1;
      puVar14 = puVar14 + 1;
    } while ((longlong)(pcVar11 + (-0x40 - param_1)) < (longlong)iVar8);
  }
  iVar8 = strncmp("LogicalDrive",(char *)(param_1 + 0x30),0xc);
  if (iVar8 == 0) {
    iVar6 = 0;
    if (!bVar2) {
      *(undefined1 *)(param_1 + 0xf0) = 1;
      *(undefined8 *)(param_1 + 0x28) = *(undefined8 *)(param_1 + 0x50);
      return 1;
    }
  }
  else {
    sprintf(local_50,"\\\\.\\%s");
    if (!bVar2) {
      uVar10 = 0;
      pvVar7 = CreateFileA(local_50,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
      *(HANDLE *)(param_1 + 0x28) = pvVar7;
      if (pvVar7 == (HANDLE)0xffffffffffffffff) {
        DVar5 = GetLastError();
        FUN_180004400("Couldn\'t open %s GetLastError returned %lu\n",local_50,(ulonglong)DVar5,
                      uVar10);
      }
      else {
        uVar16 = 0;
        uVar15 = 0;
        uVar10 = 0x90018;
        BVar4 = DeviceIoControl(pvVar7,0x90018,(LPVOID)0x0,0,(LPVOID)0x0,0,&local_54,
                                (LPOVERLAPPED)0x0);
        if (BVar4 != 0) {
          FUN_180004400("locked drive\n",uVar10,uVar15,uVar16);
          *(undefined1 *)(param_1 + 0xf0) = 1;
          return 1;
        }
        DVar5 = GetLastError();
        FUN_180004400("DeviceIoControl to lock drive failed with %u\n",(ulonglong)DVar5,uVar15,
                      uVar16);
      }
      iVar6 = -0xf;
      bVar2 = true;
    }
  }
  if (iVar12 == 0) {
    iVar12 = 1;
  }
  lVar9 = (longlong)iVar12;
  if (0 < iVar12) {
    puVar14 = (undefined8 *)(param_1 + 0x50);
    do {
      if ((HANDLE)*puVar14 != (HANDLE)0x0) {
        CloseHandle((HANDLE)*puVar14);
      }
      *puVar14 = 0;
      puVar14 = puVar14 + 1;
      lVar9 = lVar9 + -1;
    } while (lVar9 != 0);
  }
  if ((bVar2) && (iVar6 == 0)) {
    uVar10 = 0;
    pvVar7 = CreateFileA(local_50,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    *(HANDLE *)(param_1 + 0x28) = pvVar7;
    if (pvVar7 == (HANDLE)0xffffffffffffffff) {
      DVar5 = GetLastError();
      FUN_180004400("Couldn\'t open %s GetLastError returned %lu\n",local_50,(ulonglong)DVar5,uVar10
                   );
      iVar6 = -0xf;
    }
    else {
      iVar6 = 2;
    }
  }
  return iVar6;
}

