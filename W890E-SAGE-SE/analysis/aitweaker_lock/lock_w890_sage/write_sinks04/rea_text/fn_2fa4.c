
longlong Observed_SetupExtractConfig
                   (longlong param_1,wchar_t *param_2,longlong *param_3,undefined8 param_4)

{
  wchar_t *pwVar1;
  longlong lVar2;
  wchar_t wVar3;
  longlong lVar4;
  longlong lVar5;
  wchar_t *pwVar6;
  longlong lVar7;
  wchar_t *pwVar8;
  longlong local_res8;
  undefined8 local_res10;
  undefined8 local_118 [2];
  undefined4 local_108;
  undefined4 uStack_104;
  undefined4 uStack_100;
  undefined4 uStack_fc;
  longlong local_f8;
  undefined1 local_f0 [24];
  undefined1 local_d8 [160];
  
  lVar4 = 0;
  local_res10 = 0;
  local_f8 = 0;
  if (param_2 == (wchar_t *)0x0) {
    local_108 = *(undefined4 *)(param_1 + 0x28);
    uStack_104 = *(undefined4 *)(param_1 + 0x2c);
    uStack_100 = *(undefined4 *)(param_1 + 0x30);
    uStack_fc = *(undefined4 *)(param_1 + 0x34);
    lVar4 = FUN_00002b48(*(undefined8 *)(param_1 + 0x20),*(undefined8 *)(param_1 + 0x18),&local_108,
                         param_4,param_3);
    if (lVar4 < 0) {
      return -0x7ffffffffffffff2;
    }
    return lVar4;
  }
  lVar5 = (**(code **)(DAT_000483d8 + 0x140))(&DAT_0002c2f8,0,&local_f8);
  if (lVar5 < 0) {
    return lVar5;
  }
  if ((param_2 == u_GUID__000417a8) ||
     (lVar5 = FUN_00001040(param_2,u_GUID__000417a8,10), lVar5 == 0)) {
    FUN_000024d8(param_2 + 5,0x20,local_f0);
    pwVar6 = param_2 + 0x25;
    if (*pwVar6 == L'&') {
      if ((param_2 + 0x26 != u_NAME__000417b8) &&
         (lVar5 = FUN_00001040(param_2 + 0x26,u_NAME__000417b8,10), lVar5 != 0)) {
        *param_3 = (longlong)pwVar6;
        return -0x7ffffffffffffffe;
      }
      local_res8 = 0x50;
      FUN_00002558(param_2 + 0x2b,&local_res8,local_d8);
      pwVar1 = param_2 + 0x2b + local_res8 * 4;
      if (*pwVar1 != L'&') {
        *param_3 = (longlong)pwVar6;
        return -0x7ffffffffffffffe;
      }
      local_res8 = 0;
      lVar5 = (**(code **)(DAT_000483e8 + 0x48))(local_d8,local_f0,0,&local_res8,local_res10);
      if (lVar5 == -0x7ffffffffffffffb) {
        (**(code **)(DAT_000483d8 + 0x40))(4,local_res8,&local_res10);
        lVar5 = (**(code **)(DAT_000483e8 + 0x48))(local_d8,local_f0,0,&local_res8,local_res10);
      }
      pwVar6 = pwVar1;
      if (lVar5 < 0) {
        *param_3 = (longlong)param_2;
        return lVar5;
      }
      do {
        pwVar8 = pwVar6 + 1;
        if (*pwVar8 == L'&') {
          if ((pwVar6 + 2 != u_OFFSET__000417d8) &&
             (lVar5 = FUN_00001040(pwVar6 + 2,u_OFFSET__000417d8,0xe), lVar4 = DAT_000483d8,
             lVar5 != 0)) {
            *param_3 = (longlong)pwVar8;
            (**(code **)(lVar4 + 0x48))(local_res10);
            return -0x7ffffffffffffffe;
          }
          lVar5 = (**(code **)(local_f8 + 0x18))
                            (local_f8,param_2,local_res10,local_res8,param_4,param_3);
          goto LAB_00003369;
        }
        pwVar6 = pwVar8;
      } while (*pwVar8 != L'\0');
      pwVar6 = u__OFFSET_0_WIDTH__00041820;
      lVar5 = lVar4;
      do {
        pwVar6 = pwVar6 + 1;
        lVar5 = lVar5 + 1;
      } while (*pwVar6 != L'\0');
      lVar2 = lVar5 * 2 + 0x12;
      lVar7 = (**(code **)(DAT_000483d8 + 0x40))(4,lVar2,local_118);
      lVar5 = DAT_000483d8;
      if (lVar7 < 0) {
        *param_3 = (longlong)pwVar1;
        (**(code **)(lVar5 + 0x48))(local_res10);
        return -0x7ffffffffffffff7;
      }
      (**(code **)(DAT_000483d8 + 0x168))(local_118[0],lVar2,0);
      FUN_0001e3ac(local_118[0],lVar2,u__OFFSET_0_WIDTH__x_00041848,local_res8);
      wVar3 = *param_2;
      lVar5 = lVar4;
      pwVar6 = param_2;
      while (wVar3 != L'\0') {
        pwVar6 = pwVar6 + 1;
        lVar5 = lVar5 + 1;
        wVar3 = *pwVar6;
      }
      lVar2 = lVar2 + (lVar5 + 1) * 2;
      lVar7 = (**(code **)(DAT_000483d8 + 0x40))(4,lVar2,&local_108);
      lVar5 = DAT_000483d8;
      if (lVar7 < 0) {
        *param_3 = (longlong)pwVar1;
        (**(code **)(lVar5 + 0x48))(local_118[0]);
        lVar5 = -0x7ffffffffffffff7;
      }
      else {
        (**(code **)(DAT_000483d8 + 0x168))(CONCAT44(uStack_104,local_108),lVar2,0);
        lVar5 = FUN_0001f9c0(CONCAT44(uStack_104,local_108),lVar2,param_2);
        if ((lVar5 < 0) ||
           (lVar5 = FUN_0001f9c0(CONCAT44(uStack_104,local_108),lVar2,local_118[0]), lVar5 < 0)) {
          *param_3 = (longlong)pwVar1;
        }
        else {
          lVar5 = (**(code **)(local_f8 + 0x18))
                            (local_f8,CONCAT44(uStack_104,local_108),local_res10,local_res8,param_4,
                             param_3);
          wVar3 = *param_2;
          pwVar6 = param_2;
          while (wVar3 != L'\0') {
            pwVar6 = pwVar6 + 1;
            lVar4 = lVar4 + 1;
            wVar3 = *pwVar6;
          }
          *param_3 = (longlong)(param_2 + lVar4);
        }
        (**(code **)(DAT_000483d8 + 0x48))(local_118[0]);
        (**(code **)(DAT_000483d8 + 0x48))(CONCAT44(uStack_104,local_108));
      }
LAB_00003369:
      (**(code **)(DAT_000483d8 + 0x48))(local_res10);
      return lVar5;
    }
  }
  *param_3 = (longlong)param_2;
  return -0x7ffffffffffffffe;
}

