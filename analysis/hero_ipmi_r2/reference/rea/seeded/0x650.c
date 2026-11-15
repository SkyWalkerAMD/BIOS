
/* WARNING: Type propagation algorithm not settling */

void BmcSetupCallback_from_event(undefined8 param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  int local_res18 [2];
  int local_res20 [2];
  ulonglong local_48;
  longlong local_40;
  longlong local_38;
  longlong local_30 [2];
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  local_30[1] = 0;
  local_38 = 0;
  local_30[0] = 0;
  local_48 = 0;
  local_40 = 0;
  local_20 = 0xbb31e7e8;
  local_1c = 0x43ca94e0;
  local_18 = 0x4c69d0aa;
  local_14 = 0x5cffb3fa;
  lVar1 = (**(code **)(DAT_000013d8 + 0x40))(4,0x80,&local_38);
  if ((-1 < lVar1) &&
     (lVar1 = (**(code **)(DAT_000013d8 + 0x80))(local_30 + 1,&local_20,0,local_38), -1 < lVar1)) {
    lVar1 = (**(code **)(DAT_000013d8 + 0x138))(2,&DAT_000012d0,0,&local_48,local_30);
    if ((-1 < lVar1) && (uVar2 = 0, local_48 != 0)) {
      do {
        lVar1 = (**(code **)(DAT_000013d8 + 0x98))
                          (*(undefined8 *)(local_30[0] + uVar2 * 8),&DAT_000012d0,&local_40);
        if (((-1 < lVar1) &&
            (lVar1 = (**(code **)(local_40 + 0x30))(local_40,2,0,1,local_res20), -1 < lVar1)) &&
           (local_res20[0] == 0x24021a03)) {
          local_res18[0] = 0;
          lVar1 = (**(code **)(local_40 + 0x30))(local_40,2,0x14,1,local_res18);
          if (lVar1 < 0) {
            local_res18[0] = -1;
          }
          else {
            local_res18[0] = local_res18[0] + 0xe88;
          }
          *(int *)(local_38 + 4) = local_res18[0];
          break;
        }
        uVar2 = uVar2 + 1;
      } while (uVar2 < local_48);
    }
    (**(code **)(DAT_000013d8 + 0x70))(param_1);
  }
  return;
}

