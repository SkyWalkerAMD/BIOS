
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void WS05_1394(longlong param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  byte bVar3;
  ulonglong uVar4;
  undefined1 local_res8 [16];
  undefined *local_res18;
  longlong local_res20;
  longlong local_1828 [2];
  undefined8 local_1818;
  undefined4 uStack_1810;
  undefined4 uStack_180c;
  undefined1 local_1808 [157];
  char acStack_176b [5987];
  
  local_res20 = 0;
  local_1828[0] = 0;
  local_res18 = &DAT_000017fe;
  if (param_1 != 0) {
    (**(code **)(DAT_00002108 + 0x70))();
  }
  lVar1 = (**(code **)(DAT_00002110 + 0x48))
                    (u_SocketIioConfig_00002090,&DAT_00002038,local_res8,&local_res18,local_1808);
  if ((-1 < lVar1) &&
     (lVar1 = (**(code **)(DAT_00002108 + 0x140))(&DAT_00002068,0,&local_res20), -1 < lVar1)) {
    local_1818 = CONCAT44(uRam000000000000203c,_DAT_00002038);
    uStack_1810 = uRam0000000000002040;
    uStack_180c = uRam0000000000002044;
    lVar1 = (**(code **)(local_res20 + 0x20))
                      (u_SocketIioConfig_00002090,&local_1818,local_1828,&local_res18);
    if (-1 < lVar1) {
      uVar2 = 0;
      do {
        uVar4 = 0;
        do {
          lVar1 = uVar4 * 0x3c + uVar2 * 0x1f1;
          if ((*(char *)(lVar1 + 0x9d + local_1828[0]) == '\0') && (acStack_176b[lVar1] == '\x01'))
          {
            local_1818 = 0;
            (**(code **)(DAT_00002108 + 0x80))(&local_1818,&DAT_00002058,0,0);
            return;
          }
          bVar3 = (char)uVar4 + 1;
          uVar4 = (ulonglong)bVar3;
        } while (bVar3 < 8);
        bVar3 = (char)uVar2 + 1;
        uVar2 = (ulonglong)bVar3;
      } while (bVar3 < 10);
    }
  }
  return;
}

