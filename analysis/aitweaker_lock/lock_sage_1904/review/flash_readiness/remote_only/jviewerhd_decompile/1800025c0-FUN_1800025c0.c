
undefined8 FUN_1800025c0(longlong param_1)

{
  char cVar1;
  BOOL BVar2;
  DWORD DVar3;
  undefined **ppuVar4;
  ulonglong uVar5;
  char *pcVar6;
  undefined8 *puVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  DWORD local_res8 [2];
  
  if (*(char *)(param_1 + 0xf0) != '\0') {
    uVar9 = 0;
    uVar8 = 0;
    BVar2 = DeviceIoControl(*(HANDLE *)(param_1 + 0x28),0x9001c,(LPVOID)0x0,0,(LPVOID)0x0,0,
                            local_res8,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      FUN_180004400("DeviceIoControl to un lock drive failed with %u\n",(ulonglong)DVar3,uVar8,uVar9
                   );
    }
    uVar9 = 0;
    uVar8 = 0;
    local_res8[0] = 0;
    BVar2 = DeviceIoControl(*(HANDLE *)(param_1 + 0x28),0x70140,(LPVOID)0x0,0,(LPVOID)0x0,0,
                            local_res8,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      FUN_180004400("DeviceIoControl to DISK update failed with %u\n",(ulonglong)DVar3,uVar8,uVar9);
      ppuVar4 = FUN_1800066b8();
      fflush((FILE *)(ppuVar4 + 6));
    }
    uVar5 = 0xffffffffffffffff;
    pcVar6 = (char *)(param_1 + 0x40);
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    if (0 < (int)(~uVar5 - 2)) {
      puVar7 = (undefined8 *)(param_1 + 0x50);
      uVar5 = ~uVar5 - 2 & 0xffffffff;
      do {
        CloseHandle((HANDLE)*puVar7);
        *puVar7 = 0;
        puVar7 = puVar7 + 1;
        uVar5 = uVar5 - 1;
      } while (uVar5 != 0);
    }
    *(undefined1 *)(param_1 + 0xf0) = 0;
  }
  CloseHandle(*(HANDLE *)(param_1 + 0x28));
  return 0;
}

