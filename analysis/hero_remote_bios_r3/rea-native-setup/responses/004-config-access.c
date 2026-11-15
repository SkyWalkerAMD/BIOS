
longlong HeroExtractConfig(longlong param_1,short *param_2,longlong *param_3,undefined8 param_4)

{
  short *psVar1;
  longlong lVar2;
  short sVar3;
  longlong lVar4;
  longlong lVar5;
  wchar_t *pwVar6;
  longlong lVar7;
  short *psVar8;
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
  short *psVar9;
  
  lVar4 = 0;
  local_res10 = 0;
  local_f8 = 0;
  if (param_2 == (short *)0x0) {
    local_108 = *(undefined4 *)(param_1 + 0x28);
    uStack_104 = *(undefined4 *)(param_1 + 0x2c);
    uStack_100 = *(undefined4 *)(param_1 + 0x30);
    uStack_fc = *(undefined4 *)(param_1 + 0x34);
    lVar4 = FUN_0000754c(*(undefined8 *)(param_1 + 0x20),*(undefined8 *)(param_1 + 0x18),&local_108,
                         param_4,param_3);
    if (lVar4 < 0) {
      return -0x7ffffffffffffff2;
    }
    return lVar4;
  }
  lVar5 = (**(code **)(DAT_00071f68 + 0x140))(&DAT_00048020,0,&local_f8);
  if (lVar5 < 0) {
    return lVar5;
  }
  lVar5 = lVar4;
  if (param_2 != (short *)PTR_u_GUID__000673b8) {
    lVar5 = FUN_00000320(param_2,PTR_u_GUID__000673b8,10);
  }
  if (lVar5 == 0) {
    local_res8 = 0x20;
    FUN_00006f20(param_2 + 5,0x20,local_f0);
    psVar8 = param_2 + 0x25;
    if (*psVar8 == 0x26) {
      lVar5 = lVar4;
      if (param_2 + 0x26 != (short *)PTR_u_NAME__000673a8) {
        lVar5 = FUN_00000320(param_2 + 0x26,PTR_u_NAME__000673a8,10);
      }
      if (lVar5 != 0) {
        *param_3 = (longlong)psVar8;
        return -0x7ffffffffffffffe;
      }
      local_res8 = 0x50;
      FUN_00006fa0(param_2 + 0x2b,&local_res8,local_d8);
      psVar1 = param_2 + 0x2b + local_res8 * 4;
      if (*psVar1 != 0x26) {
        *param_3 = (longlong)psVar8;
        return -0x7ffffffffffffffe;
      }
      local_res8 = 0;
      lVar5 = (**(code **)(DAT_00071f78 + 0x48))(local_d8,local_f0,0,&local_res8,local_res10);
      if (lVar5 == -0x7ffffffffffffffb) {
        (**(code **)(DAT_00071f68 + 0x40))(4,local_res8,&local_res10);
        lVar5 = (**(code **)(DAT_00071f78 + 0x48))(local_d8,local_f0,0,&local_res8,local_res10);
      }
      psVar8 = psVar1;
      if (lVar5 < 0) {
        *param_3 = (longlong)param_2;
        return lVar5;
      }
      do {
        psVar9 = psVar8 + 1;
        if (*psVar9 == 0x26) {
          if (psVar8 + 2 != (short *)PTR_u_OFFSET__00067398) {
            lVar4 = FUN_00000320(psVar8 + 2,PTR_u_OFFSET__00067398,0xe);
          }
          lVar5 = DAT_00071f68;
          if (lVar4 != 0) {
            *param_3 = (longlong)psVar9;
            (**(code **)(lVar5 + 0x48))(local_res10);
            return -0x7ffffffffffffffe;
          }
          lVar5 = (**(code **)(local_f8 + 0x18))
                            (local_f8,param_2,local_res10,local_res8,param_4,param_3);
          goto LAB_00007c9d;
        }
        psVar8 = psVar9;
      } while (*psVar9 != 0);
      pwVar6 = u__OFFSET_0_WIDTH__00067340;
      lVar5 = lVar4;
      do {
        pwVar6 = pwVar6 + 1;
        lVar5 = lVar5 + 1;
      } while (*pwVar6 != L'\0');
      lVar2 = lVar5 * 2 + 0x12;
      lVar7 = (**(code **)(DAT_00071f68 + 0x40))(4,lVar2,local_118);
      lVar5 = DAT_00071f68;
      if (lVar7 < 0) {
        *param_3 = (longlong)psVar1;
        (**(code **)(lVar5 + 0x48))(local_res10);
        return -0x7ffffffffffffff7;
      }
      (**(code **)(DAT_00071f68 + 0x168))(local_118[0],lVar2,0);
      FUN_0003014c(local_118[0],lVar2,u__OFFSET_0_WIDTH__x_00067368,local_res8);
      sVar3 = *param_2;
      lVar5 = lVar4;
      psVar8 = param_2;
      while (sVar3 != 0) {
        psVar8 = psVar8 + 1;
        lVar5 = lVar5 + 1;
        sVar3 = *psVar8;
      }
      lVar2 = lVar2 + (lVar5 + 1) * 2;
      lVar7 = (**(code **)(DAT_00071f68 + 0x40))(4,lVar2,&local_108);
      lVar5 = DAT_00071f68;
      if (lVar7 < 0) {
        *param_3 = (longlong)psVar1;
        (**(code **)(lVar5 + 0x48))(local_118[0]);
        lVar5 = -0x7ffffffffffffff7;
      }
      else {
        (**(code **)(DAT_00071f68 + 0x168))(CONCAT44(uStack_104,local_108),lVar2,0);
        lVar5 = FUN_000315c8(CONCAT44(uStack_104,local_108),lVar2,param_2);
        if ((lVar5 < 0) ||
           (lVar5 = FUN_000315c8(CONCAT44(uStack_104,local_108),lVar2,local_118[0]), lVar5 < 0)) {
          *param_3 = (longlong)psVar1;
        }
        else {
          lVar5 = (**(code **)(local_f8 + 0x18))
                            (local_f8,CONCAT44(uStack_104,local_108),local_res10,local_res8,param_4,
                             param_3);
          sVar3 = *param_2;
          psVar8 = param_2;
          while (sVar3 != 0) {
            psVar8 = psVar8 + 1;
            lVar4 = lVar4 + 1;
            sVar3 = *psVar8;
          }
          *param_3 = (longlong)(param_2 + lVar4);
        }
        (**(code **)(DAT_00071f68 + 0x48))(local_118[0]);
        (**(code **)(DAT_00071f68 + 0x48))(CONCAT44(uStack_104,local_108));
      }
LAB_00007c9d:
      (**(code **)(DAT_00071f68 + 0x48))(local_res10);
      return lVar5;
    }
  }
  *param_3 = (longlong)param_2;
  return -0x7ffffffffffffffe;
}



longlong HeroRouteConfig(ulonglong param_1,undefined *param_2,longlong *param_3)

{
  longlong lVar1;
  longlong lVar2;
  undefined *puVar3;
  ulonglong local_res8;
  longlong local_res10 [2];
  longlong local_res20;
  longlong local_e8;
  undefined1 local_e0 [16];
  undefined1 local_d0 [8];
  undefined1 local_c8 [160];
  
  local_res20 = 0;
  if (param_2 == (undefined *)0x0) {
    *param_3 = 0;
  }
  else {
    local_res8 = param_1;
    lVar1 = (**(code **)(DAT_00071f68 + 0x140))(&DAT_00048020,0,&local_e8);
    if (lVar1 < 0) {
      return lVar1;
    }
    if (param_2 == PTR_u_GUID__000673b8) {
      lVar1 = 0;
    }
    else {
      lVar1 = FUN_00000320(param_2,PTR_u_GUID__000673b8,10);
    }
    if (lVar1 == 0) {
      lVar1 = FUN_0000724c(param_2,local_d0);
      if (lVar1 < 0) {
        return -0x7ffffffffffffff2;
      }
      local_res10[0] = 0x20;
      FUN_00006f20(param_2 + 10,0x20,local_e0);
      if (*(short *)(param_2 + 0x4a) == 0x26) {
        if (param_2 + 0x4c == PTR_u_NAME__000673a8) {
          lVar1 = 0;
        }
        else {
          lVar1 = FUN_00000320(param_2 + 0x4c,PTR_u_NAME__000673a8,10);
        }
        if (lVar1 == 0) {
          puVar3 = param_2 + 0x56;
          local_res10[0] = 0x50;
          FUN_00006fa0(puVar3,local_res10,local_c8);
          if (*(short *)(puVar3 + local_res10[0] * 8) != 0x26) {
            *param_3 = (longlong)(puVar3 + local_res10[0] * 8);
            return -0x7ffffffffffffffe;
          }
          local_res10[0] = 0;
          lVar1 = (**(code **)(DAT_00071f78 + 0x48))
                            (local_c8,local_e0,&local_res8,local_res10,local_res20);
          if (lVar1 == -0x7ffffffffffffffb) {
            (**(code **)(DAT_00071f68 + 0x40))(4,local_res10[0],&local_res20);
            lVar1 = (**(code **)(DAT_00071f78 + 0x48))
                              (local_c8,local_e0,&local_res8,local_res10,local_res20);
          }
          if (lVar1 < 0) {
            if (local_res20 != 0) {
              (**(code **)(DAT_00071f68 + 0x48))();
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
                if (-1 < lVar2) {
                  lVar1 = (**(code **)(DAT_00071f78 + 0x58))
                                    (local_c8,local_e0,local_res8 & 0xffffffff,lVar1,local_res20);
                  (**(code **)(DAT_00071f68 + 0x48))(local_res20);
                  return lVar1;
                }
                return lVar2;
              }
              if (local_res20 != 0) {
                return -0x7ffffffffffffffe;
              }
            }
            if (local_res20 != 0) {
              (**(code **)(DAT_00071f68 + 0x48))();
            }
            lVar2 = (**(code **)(DAT_00071f68 + 0x40))(4,local_res10[0],&local_res20);
            lVar1 = local_res10[0];
            if (lVar2 < 0) {
              return lVar2;
            }
            lVar2 = (**(code **)(local_e8 + 0x20))(local_e8,param_2,local_res20,local_res10,param_3)
            ;
          } while( true );
        }
      }
      *param_3 = (longlong)(param_2 + 0x4a);
    }
    else {
      *param_3 = (longlong)param_2;
    }
  }
  return -0x7ffffffffffffffe;
}



longlong HeroConfigCallback(undefined8 param_1,undefined8 param_2,short param_3,undefined1 param_4,
                           undefined8 param_5,undefined8 *param_6)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 *puVar3;
  longlong lVar4;
  undefined8 local_38;
  undefined8 local_30;
  short local_28;
  undefined1 local_26;
  undefined8 local_20;
  undefined8 *local_18;
  undefined8 local_10;
  
  local_20 = param_5;
  local_10 = DAT_0004bb30;
  local_18 = param_6;
  if (param_6 != (undefined8 *)0x0) {
    *param_6 = 0;
  }
  lVar2 = 0;
  DAT_00071cf0 = &local_38;
  lVar1 = -0x7ffffffffffffffd;
  puVar3 = DAT_000788a0;
  local_38 = param_1;
  local_30 = param_2;
  local_28 = param_3;
  local_26 = param_4;
  if (PTR_FUN_000484b8 != (undefined *)0x0) {
    lVar4 = 0;
    do {
      if (*(short *)((longlong)&DAT_000484b4 + lVar4) == param_3) {
        DAT_00071ce0 = 1;
        lVar1 = (**(code **)((longlong)&PTR_FUN_000484b8 + lVar4))(DAT_0004bb30,1,0,param_3);
        DAT_00071ce0 = 0;
        if ((DAT_00071cf0[1] == 0x1000) && (puVar3 = DAT_000788a0, lVar1 != -0x7ffffffffffffffd))
        break;
      }
      lVar2 = lVar2 + 1;
      lVar4 = lVar2 * 0x10;
      puVar3 = DAT_000788a0;
    } while ((&PTR_FUN_000484b8)[lVar2 * 2] != (undefined *)0x0);
  }
  while (((undefined8 **)puVar3 != &DAT_000788a0 &&
         ((*(short *)(puVar3 + 2) != param_3 ||
          (lVar1 = (*(code *)puVar3[3])(&local_38), lVar1 == -0x7ffffffffffffffd))))) {
    puVar3 = (undefined8 *)*puVar3;
  }
  DAT_00071cf0 = (undefined8 *)0x0;
  return lVar1;
}

