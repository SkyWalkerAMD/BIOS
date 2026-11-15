
longlong Candidate_RouteConfig_Body(ulonglong param_1,short *param_2,longlong *param_3)

{
  longlong lVar1;
  short *psVar2;
  ulonglong uVar3;
  ulonglong local_res8;
  ulonglong local_res10 [2];
  longlong local_res20;
  longlong local_e8;
  byte local_e0 [16];
  undefined1 local_d0 [8];
  undefined1 local_c8 [160];
  
  local_res20 = 0;
  if (param_2 == (short *)0x0) {
    *param_3 = 0;
  }
  else {
    local_res8 = param_1;
    lVar1 = (**(code **)(DAT_00043280 + 0x140))(&DAT_00027a80,0,&local_e8);
    if (lVar1 < 0) {
      return lVar1;
    }
    if (param_2 == (short *)PTR_u_GUID__0003cb08) {
      lVar1 = 0;
    }
    else {
      lVar1 = FUN_00000340((char *)param_2,PTR_u_GUID__0003cb08,10);
    }
    if (lVar1 == 0) {
      lVar1 = FUN_00001ae8(param_2,local_d0);
      if (lVar1 < 0) {
        return -0x7ffffffffffffff2;
      }
      local_res10[0] = 0x20;
      FUN_000017bc((longlong)(param_2 + 5),0x20,local_e0);
      if (param_2[0x25] == 0x26) {
        if (param_2 + 0x26 == (short *)PTR_u_NAME__0003caf8) {
          lVar1 = 0;
        }
        else {
          lVar1 = FUN_00000340((char *)(param_2 + 0x26),PTR_u_NAME__0003caf8,10);
        }
        if (lVar1 == 0) {
          psVar2 = param_2 + 0x2b;
          local_res10[0] = 0x50;
          FUN_0000183c((longlong)psVar2,local_res10,(longlong)local_c8);
          if (psVar2[local_res10[0] * 4] != 0x26) {
            *param_3 = (longlong)(psVar2 + local_res10[0] * 4);
            return -0x7ffffffffffffffe;
          }
          local_res10[0] = 0;
          lVar1 = (**(code **)(DAT_00043290 + 0x48))
                            (local_c8,local_e0,&local_res8,local_res10,local_res20);
          if (lVar1 == -0x7ffffffffffffffb) {
            (**(code **)(DAT_00043280 + 0x40))(4,local_res10[0],&local_res20);
            lVar1 = (**(code **)(DAT_00043290 + 0x48))
                              (local_c8,local_e0,&local_res8,local_res10,local_res20);
          }
          if (lVar1 < 0) {
            if (local_res20 != 0) {
              (**(code **)(DAT_00043280 + 0x48))();
            }
            local_res8 = CONCAT44(local_res8._4_4_,7);
            local_res20 = 0;
            local_res10[0] = 0;
          }
          uVar3 = local_res10[0];
          lVar1 = (**(code **)(local_e8 + 0x20))(local_e8,param_2,local_res20,local_res10,param_3);
          do {
            if (lVar1 != -0x7ffffffffffffff9) {
              if (lVar1 != -0x7ffffffffffffffe) {
                if (-1 < lVar1) {
                  lVar1 = (**(code **)(DAT_00043290 + 0x58))
                                    (local_c8,local_e0,local_res8 & 0xffffffff,uVar3,local_res20);
                  (**(code **)(DAT_00043280 + 0x48))(local_res20);
                  return lVar1;
                }
                return lVar1;
              }
              if (local_res20 != 0) {
                return -0x7ffffffffffffffe;
              }
            }
            if (local_res20 != 0) {
              (**(code **)(DAT_00043280 + 0x48))();
            }
            lVar1 = (**(code **)(DAT_00043280 + 0x40))(4,local_res10[0],&local_res20);
            uVar3 = local_res10[0];
            if (lVar1 < 0) {
              return lVar1;
            }
            lVar1 = (**(code **)(local_e8 + 0x20))(local_e8,param_2,local_res20,local_res10,param_3)
            ;
          } while( true );
        }
      }
      *param_3 = (longlong)(param_2 + 0x25);
    }
    else {
      *param_3 = (longlong)param_2;
    }
  }
  return -0x7ffffffffffffffe;
}

