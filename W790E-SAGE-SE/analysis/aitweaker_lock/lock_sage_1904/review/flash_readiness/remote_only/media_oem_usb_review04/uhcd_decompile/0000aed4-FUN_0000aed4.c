
void FUN_0000aed4(undefined8 param_1,undefined8 param_2,longlong param_3)

{
  longlong lVar1;
  undefined8 local_res8;
  undefined8 *local_res20;
  char local_28 [32];
  
  local_res8 = param_1;
  lVar1 = (**(code **)(DAT_000104c0 + 0x40))(4);
  if (-1 < lVar1) {
    FUN_0000e644(1,0x1020000);
    FUN_00000340(local_res20,0x70,0);
    *local_res20 = 0x756f6d75;
    local_res20[5] = &LAB_0000b190;
    local_res20[4] = FUN_0000b140;
    local_res20[7] = local_res20 + 8;
    *(undefined1 *)(local_res20 + 1) = 2;
    *(undefined4 *)((longlong)local_res20 + 0x14) = 0x7f;
    *(undefined4 *)((longlong)local_res20 + 0xc) = 0x7f;
    *(undefined4 *)(local_res20 + 3) = 0xffffff81;
    *(undefined4 *)(local_res20 + 2) = 0xffffff81;
    *(undefined1 *)(local_res20 + 0xb) = 1;
    *(undefined1 *)((longlong)local_res20 + 0x59) = 1;
    local_res20[8] = 8;
    local_res20[9] = 8;
    local_res20[10] = 1;
    local_res20[0xd] = param_2;
    *(undefined1 *)(local_res20 + 0xc) = *(undefined1 *)(param_3 + 0x50);
    FUN_0000b140();
    FUN_0000e644(1,0x1020003);
    (**(code **)(DAT_000104c0 + 0x50))(0x100,0x10,&LAB_0000b368,local_res20,local_res20 + 6);
    (**(code **)(DAT_000104c0 + 0x80))(&local_res8,&DAT_0000eaa0,0,local_res20 + 4);
    FUN_0000d074(local_28,0x1e,(byte *)u_DetectUsbMs__X__X_0000fe18,
                 (ulonglong)*(ushort *)(param_3 + 6));
    FUN_0000d074(local_28,0x1e,(byte *)u_ConfigUsbMs__X__X_0000fe40,
                 (ulonglong)*(ushort *)(param_3 + 6));
    FUN_0000e644(1,0x1020004);
  }
  return;
}

