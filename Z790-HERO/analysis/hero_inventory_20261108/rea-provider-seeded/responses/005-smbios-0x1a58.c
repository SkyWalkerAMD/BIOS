
void FUN_00001a58(longlong param_1)

{
  ulonglong local_res8;
  int local_28;
  int local_24;
  int local_20;
  int local_18;
  int local_14;
  int local_10;
  
  local_res8 = 0xc;
  FUN_000002c0((undefined8 *)&local_28,0xc);
  if (local_res8 != 0) {
    FUN_000002c0((undefined8 *)&local_18,local_res8);
  }
  if (*(longlong *)(param_1 + 0x330) != 0) {
    FUN_000014e0(param_1,&local_28);
  }
  (**(code **)(DAT_00018a30 + 0x48))
            (u_AmiSysInventoryCrc_000165a0,&DAT_00016520,0,&local_res8,&local_18);
  if (local_18 != local_28) {
    *(undefined1 *)(param_1 + 0x24) = 1;
  }
  if (local_14 != local_24) {
    *(undefined1 *)(param_1 + 0x25) = 1;
  }
  if (local_10 != local_20) {
    *(undefined1 *)(param_1 + 0x26) = 1;
  }
  if (local_10 != local_20 || (local_14 != local_24 || local_18 != local_28)) {
    (**(code **)(DAT_00018a30 + 0x58))
              (u_AmiSysInventoryCrc_000165a0,&DAT_00016520,3,local_res8,&local_28);
  }
  return;
}

