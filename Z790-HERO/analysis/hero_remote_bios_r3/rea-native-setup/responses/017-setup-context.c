/* 0xb54 */

/* WARNING: Type propagation algorithm not settling */

void HeroSetupPublishNotify(longlong param_1)

{
  char *pcVar1;
  undefined **ppuVar2;
  char cVar3;
  ulonglong uVar4;
  longlong lVar5;
  undefined8 uVar6;
  code *pcVar7;
  longlong lVar8;
  char *pcVar9;
  uint *puVar10;
  undefined8 *puVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  ulonglong local_res18;
  char *local_res20;
  longlong local_58;
  undefined8 local_50;
  undefined8 *local_48;
  longlong local_40;
  undefined8 local_38;
  undefined1 auStack_34 [4];
  undefined8 local_30;
  undefined4 local_28;
  
  uVar14 = 0;
  local_38 = 0x140304;
  local_40 = 0;
  local_48 = (undefined8 *)0x0;
  local_58 = 0;
  local_50 = 0;
  local_30 = 0;
  local_28 = 0;
  if ((((DAT_00071ce1 == '\0') &&
       (lVar5 = (**(code **)(DAT_00071f68 + 0x140))(&DAT_00048190,0,&local_40), -1 < lVar5)) &&
      (lVar5 = (**(code **)(DAT_00071f68 + 0x140))(&DAT_00048150,0,&local_48), -1 < lVar5)) &&
     ((lVar5 = (**(code **)(DAT_00071f68 + 0x98))(DAT_00071ce8,&DAT_00047db0,&local_58), -1 < lVar5
      && (lVar5 = (**(code **)(DAT_00071f68 + 0x98))(DAT_00071ce8,&DAT_00047d40,&local_50),
         -1 < lVar5)))) {
    for (puVar10 = (uint *)(local_58 + 0x14);
        puVar10 < (uint *)((ulonglong)*(uint *)(local_58 + 0x10) + local_58);
        puVar10 = (uint *)((longlong)puVar10 + (ulonglong)(*puVar10 & 0xffffff))) {
      if (*(char *)((longlong)puVar10 + 3) == '\x02') {
        (**(code **)(DAT_00071f68 + 0x160))(auStack_34,(longlong)puVar10 + 6,0x10);
        (**(code **)(DAT_00071f68 + 0x160))(&DAT_0004bb38,(longlong)puVar10 + 6,0x10);
        break;
      }
    }
    uVar6 = FUN_00031e78(local_50,&stack0xffffffffffffffc8);
    lVar5 = (**(code **)(DAT_00071f68 + 0x148))
                      (&DAT_0004bb28,&DAT_00047f80,uVar6,&DAT_00048210,&PTR_LAB_0004bb10,0);
    if ((-1 < lVar5) &&
       (lVar5 = (*(code *)*local_48)(local_48,local_58,DAT_0004bb28,&DAT_0004bb30), -1 < lVar5)) {
      DAT_00071ce1 = '\x01';
      if (param_1 != 0) {
        (**(code **)(DAT_00071f68 + 0x70))(param_1);
      }
      pcVar7 = FUN_00000b48;
      uVar13 = uVar14;
      while (pcVar7 != (code *)0x0) {
        (*pcVar7)();
        puVar11 = &DAT_000644a8 + uVar13;
        uVar13 = uVar13 + 1;
        pcVar7 = (code *)*puVar11;
      }
      pcVar7 = FUN_0002ad78;
      uVar13 = uVar14;
      while (puVar11 = DAT_00078880, pcVar7 != (code *)0x0) {
        (*pcVar7)(DAT_0004bb30,1);
        ppuVar2 = &PTR_LAB_000644b8 + uVar13;
        uVar13 = uVar13 + 1;
        pcVar7 = (code *)*ppuVar2;
      }
      for (; lVar5 = local_40, uVar6 = DAT_0004bb30, (undefined8 **)puVar11 != &DAT_00078880;
          puVar11 = (undefined8 *)*puVar11) {
        (*(code *)puVar11[2])(DAT_0004bb30);
      }
      local_res18 = 0;
      local_res20 = (char *)0x0;
      lVar8 = (**(code **)(local_40 + 0x18))(local_40,DAT_0004bb30,0,&local_res18);
      if (lVar8 == -0x7ffffffffffffffb) {
        (**(code **)(DAT_00071f68 + 0x40))(4,local_res18,&local_res20);
        lVar8 = (**(code **)(lVar5 + 0x18))(lVar5,uVar6,local_res20,&local_res18);
      }
      if (lVar8 < 0) {
        local_res18 = 6;
        (**(code **)(DAT_00071f68 + 0x40))(4,6,&local_res20);
        (**(code **)(DAT_00071f68 + 0x160))(local_res20,s_en_US_0006440c,local_res18);
      }
      pcVar9 = local_res20;
      uVar12 = uVar14;
      uVar13 = local_res18;
      if (local_res18 != 0) {
        do {
          pcVar1 = pcVar9 + uVar12;
          uVar4 = uVar12;
          if (*pcVar1 == '\0') break;
          for (; ((uVar4 < uVar13 && (pcVar9[uVar4] != ';')) && (pcVar9[uVar4] != '\0'));
              uVar4 = uVar4 + 1) {
          }
          if ((*pcVar1 == 'x') && (pcVar1[1] == '-')) {
            if (pcVar9[uVar4] != ';') {
              if (((pcVar9[uVar4] == '\0') && (uVar12 != 0)) && (pcVar1[-1] == ';')) {
                pcVar1[-1] = '\0';
                uVar13 = uVar12 - 1;
                pcVar9 = local_res20;
                local_res18 = uVar13;
              }
              goto LAB_00000ec7;
            }
            (**(code **)(DAT_00071f68 + 0x160))(pcVar1,pcVar9 + uVar4 + 1,(uVar13 - uVar4) + -1);
            uVar13 = (uVar12 - uVar4) + local_res18 + 1;
            pcVar9 = local_res20;
            local_res18 = uVar13;
          }
          else {
LAB_00000ec7:
            uVar12 = uVar4 + 1;
          }
        } while (uVar12 < uVar13);
      }
      cVar3 = *pcVar9;
      while (cVar3 != '\0') {
        uVar14 = uVar14 + 1;
        cVar3 = pcVar9[uVar14];
      }
      local_res18 = uVar14 + 1;
      (**(code **)(DAT_00071f78 + 0x58))
                (u_PlatformLastLangCodes_00064418,&DAT_0004bb48,3,local_res18,pcVar9);
      (**(code **)(DAT_00071f68 + 0x48))(local_res20);
    }
  }
  return;
}


/* 0xf34 */

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void HeroSetupInit(void)

{
  char cVar1;
  longlong lVar2;
  char *pcVar3;
  undefined4 local_res18 [2];
  char *local_res20;
  longlong local_48;
  longlong local_40 [3];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_48 = 0;
  local_res18[0] = 0;
  local_res20 = (char *)0x0;
  DAT_000788a0 = &DAT_000788a0;
  DAT_000788a8 = &DAT_000788a0;
  DAT_00078880 = &DAT_00078880;
  DAT_00078888 = &DAT_00078880;
  _DAT_00078890 = &DAT_00078890;
  _DAT_00078898 = &DAT_00078890;
  _DAT_00078870 = &DAT_00078870;
  _DAT_00078878 = &DAT_00078870;
  local_28 = 0xec87d643;
  local_24 = 0x4bb5eba4;
  local_20 = 0x3e3fe5a1;
  local_1c = 0xa90db236;
  lVar2 = (**(code **)(DAT_00071f78 + 0x48))
                    (u_PlatformLastLangCodes_00064418,&DAT_0004bb48,0,&local_res20,0);
  if (lVar2 == -0x7ffffffffffffffb) {
    (**(code **)(DAT_00071fa8 + 0x140))(&DAT_00047de0,0,local_40 + 2);
    local_40[1] = 0xd46;
    (**(code **)(DAT_00071fa8 + 0x40))(4,0xd46,&local_48);
    lVar2 = (**(code **)(DAT_00071f78 + 0x48))
                      (u_Setup_00064448,&local_28,local_res18,local_40 + 1,local_48);
    if ((lVar2 < 0) ||
       ((*(char *)(local_48 + 0xd42) != '\x01' && (*(char *)(local_40[2] + 8) != '\x01')))) {
      FUN_000347b8(&DAT_00047cb0,0xb54,0,&DAT_00072148,&local_res20);
    }
    else {
      HeroSetupPublishNotify(0,0);
    }
    (**(code **)(DAT_00071fa8 + 0x48))(local_48);
  }
  else {
    HeroSetupPublishNotify(0);
  }
  local_40[0] = 0;
  local_res20 = (char *)0x0;
  lVar2 = FUN_00033ca0(u_PlatformLastLangCodes_00064418,&DAT_0004bb48,&local_res20,local_40);
  pcVar3 = local_res20;
  if (lVar2 < 0) {
    pcVar3 = (char *)0x0;
  }
  else if ((local_res20 != (char *)0x0) && (local_40[0] != 0)) {
    (**(code **)(DAT_00071f78 + 0x58))
              (u_PlatformLangCodes_00064458,&DAT_00047cd0,6,local_40[0],local_res20);
  }
  local_40[0] = 0;
  lVar2 = (**(code **)(DAT_00071f78 + 0x48))(u_PlatformLang_00064480,&DAT_00047cd0,0,local_40,0);
  if (lVar2 != -0x7ffffffffffffffb) {
    lVar2 = 0;
    if ((pcVar3 == (char *)0x0) || (cVar1 = *pcVar3, cVar1 == '\0')) {
      lVar2 = 6;
      (**(code **)(DAT_00071f68 + 0x40))(4,6,&local_res20);
      (**(code **)(DAT_00071f68 + 0x160))(local_res20,s_en_US_0006440c,6);
    }
    else {
      while ((cVar1 != ';' && (cVar1 != '\0'))) {
        lVar2 = lVar2 + 1;
        cVar1 = pcVar3[lVar2];
      }
      (**(code **)(DAT_00071f68 + 0x40))(4,lVar2 + 1,&local_res20);
      (**(code **)(DAT_00071f68 + 0x160))(local_res20,pcVar3,lVar2);
      local_res20[lVar2] = '\0';
    }
    (**(code **)(DAT_00071f78 + 0x58))(u_PlatformLang_00064480,&DAT_00047cd0,7,lVar2,local_res20);
    (**(code **)(DAT_00071f68 + 0x48))(local_res20);
  }
  (**(code **)(DAT_00071f68 + 0x48))(pcVar3);
  return;
}


/* 0x7ccc */

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

