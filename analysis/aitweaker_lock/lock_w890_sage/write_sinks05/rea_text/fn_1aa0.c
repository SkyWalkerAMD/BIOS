
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void WS05_1aa0(longlong param_1)

{
  longlong lVar1;
  undefined1 local_res8 [16];
  undefined8 local_res18;
  longlong local_res20;
  longlong local_1328 [2];
  undefined8 local_1318;
  undefined4 uStack_1310;
  undefined4 uStack_130c;
  undefined1 local_1308 [258];
  char local_1206;
  
  local_1328[0] = 0;
  local_res20 = 0;
  local_res18 = 0x12fe;
  if (param_1 != 0) {
    (**(code **)(DAT_00002200 + 0x70))();
  }
  lVar1 = (**(code **)(DAT_00002208 + 0x48))
                    (u_PchSetup_00002160,&DAT_000020c8,local_res8,&local_res18,local_1308);
  if (-1 < lVar1) {
    lVar1 = (**(code **)(DAT_00002200 + 0x140))(&DAT_00002108,0,&local_res20);
    if (-1 < lVar1) {
      local_1318 = CONCAT44(uRam00000000000020cc,_DAT_000020c8);
      uStack_1310 = uRam00000000000020d0;
      uStack_130c = uRam00000000000020d4;
      lVar1 = (**(code **)(local_res20 + 0x20))
                        (u_PchSetup_00002160,&local_1318,local_1328,&local_res18);
      if ((-1 < lVar1) && (*(char *)(local_1328[0] + 0x102) != local_1206)) {
        local_1318 = 0;
        (**(code **)(DAT_00002200 + 0x80))(&local_1318,&DAT_000020f8,0,0);
      }
    }
  }
  return;
}

