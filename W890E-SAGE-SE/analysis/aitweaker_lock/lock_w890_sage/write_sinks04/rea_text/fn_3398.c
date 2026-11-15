
longlong Observed_SetupRouteConfig(ulonglong param_1,wchar_t *param_2,longlong *param_3)

{
  longlong lVar1;
  longlong lVar2;
  wchar_t *pwVar3;
  ulonglong local_res8;
  longlong local_res10 [2];
  longlong local_res20;
  longlong local_e8;
  undefined1 local_e0 [16];
  undefined1 local_d0 [8];
  undefined1 local_c8 [160];
  
  local_res20 = 0;
  if (param_2 == (wchar_t *)0x0) {
    *param_3 = 0;
  }
  else {
    local_res8 = param_1;
    lVar1 = (**(code **)(DAT_000483d8 + 0x140))(&DAT_0002c2f8,0,&local_e8);
    if (lVar1 < 0) {
      return lVar1;
    }
    if ((param_2 == u_GUID__000417a8) ||
       (lVar1 = FUN_00001040(param_2,u_GUID__000417a8,10), lVar1 == 0)) {
      lVar1 = FUN_00002824(param_2,local_d0);
      if (lVar1 < 0) {
        return -0x7ffffffffffffff2;
      }
      FUN_000024d8(param_2 + 5,0x20,local_e0);
      if ((param_2[0x25] == L'&') &&
         ((param_2 + 0x26 == u_NAME__000417b8 ||
          (lVar1 = FUN_00001040(param_2 + 0x26,u_NAME__000417b8,10), lVar1 == 0)))) {
        pwVar3 = param_2 + 0x2b;
        local_res10[0] = 0x50;
        FUN_00002558(pwVar3,local_res10,local_c8);
        if (pwVar3[local_res10[0] * 4] == L'&') {
          local_res10[0] = 0;
          lVar1 = (**(code **)(DAT_000483e8 + 0x48))
                            (local_c8,local_e0,&local_res8,local_res10,local_res20);
          if (lVar1 == -0x7ffffffffffffffb) {
            (**(code **)(DAT_000483d8 + 0x40))(4,local_res10[0],&local_res20);
            lVar1 = (**(code **)(DAT_000483e8 + 0x48))
                              (local_c8,local_e0,&local_res8,local_res10,local_res20);
          }
          if (lVar1 < 0) {
            if (local_res20 != 0) {
              (**(code **)(DAT_000483d8 + 0x48))();
            }
            local_res8 = CONCAT44(local_res8._4_4_,7);
            local_res20 = 0;
            local_res10[0] = 0;
          }
          lVar1 = local_res10[0];
          lVar2 = (**(code **)(local_e8 + 0x20))(local_e8,param_2,local_res20,local_res10,param_3);
          do {
            if (lVar2 != -0x7ffffffffffffff9) {
              if (lVar2 != -0x7ffffffffffffffe) {
                if (lVar2 < 0) {
                  return lVar2;
                }
                lVar1 = (**(code **)(DAT_000483e8 + 0x58))
                                  (local_c8,local_e0,local_res8 & 0xffffffff,lVar1,local_res20);
                if (lVar1 == -0x7fffffffffffffe6) {
                  lVar1 = -0x7ffffffffffffff1;
                }
                (**(code **)(DAT_000483d8 + 0x48))(local_res20);
                return lVar1;
              }
              if (local_res20 != 0) {
                return -0x7ffffffffffffffe;
              }
            }
            if (local_res20 != 0) {
              (**(code **)(DAT_000483d8 + 0x48))();
            }
            lVar2 = (**(code **)(DAT_000483d8 + 0x40))(4,local_res10[0],&local_res20);
            lVar1 = local_res10[0];
            if (lVar2 < 0) {
              return lVar2;
            }
            lVar2 = (**(code **)(local_e8 + 0x20))(local_e8,param_2,local_res20,local_res10,param_3)
            ;
          } while( true );
        }
        *param_3 = (longlong)(pwVar3 + local_res10[0] * 4);
      }
      else {
        *param_3 = (longlong)(param_2 + 0x25);
      }
    }
    else {
      *param_3 = (longlong)param_2;
    }
  }
  return -0x7ffffffffffffffe;
}

