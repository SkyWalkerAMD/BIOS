/* 0xb54 */

/* WARNING: Type propagation algorithm not settling */

void HeroBeforeSaveNotify(longlong param_1)

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


/* 0x10a6 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void HeroSetupInitSeed(void)

{
  char cVar1;
  longlong lVar2;
  char *pcVar3;
  longlong unaff_RBP;
  
  *(undefined8 *)(unaff_RBP + -0x30) = 0;
  *(undefined4 *)(unaff_RBP + 0x30) = 0;
  *(undefined8 *)(unaff_RBP + 0x38) = 0;
  lVar2 = DAT_00071f78;
  DAT_000788a0 = &DAT_000788a0;
  DAT_000788a8 = &DAT_000788a0;
  DAT_00078880 = &DAT_00078880;
  DAT_00078888 = &DAT_00078880;
  _DAT_00078890 = &DAT_00078890;
  _DAT_00078898 = &DAT_00078890;
  _DAT_00078870 = &DAT_00078870;
  _DAT_00078878 = &DAT_00078870;
  *(undefined4 *)(unaff_RBP + -0x10) = 0xec87d643;
  *(undefined4 *)(unaff_RBP + -0xc) = 0x4bb5eba4;
  *(undefined4 *)(unaff_RBP + -8) = 0x3e3fe5a1;
  *(undefined4 *)(unaff_RBP + -4) = 0xa90db236;
  lVar2 = (**(code **)(lVar2 + 0x48))
                    (u_PlatformLastLangCodes_00064418,&DAT_0004bb48,0,unaff_RBP + 0x38,0);
  if (lVar2 == -0x7ffffffffffffffb) {
    (**(code **)(DAT_00071fa8 + 0x140))(&DAT_00047de0,0,unaff_RBP + -0x18);
    lVar2 = DAT_00071fa8;
    *(undefined8 *)(unaff_RBP + -0x20) = 0xd46;
    (**(code **)(lVar2 + 0x40))(4,0xd46,unaff_RBP + -0x30);
    lVar2 = (**(code **)(DAT_00071f78 + 0x48))
                      (u_Setup_00064448,unaff_RBP + -0x10,unaff_RBP + 0x30,unaff_RBP + -0x20,
                       *(undefined8 *)(unaff_RBP + -0x30));
    if ((lVar2 < 0) ||
       ((*(char *)(*(longlong *)(unaff_RBP + -0x30) + 0xd42) != '\x01' &&
        (*(char *)(*(longlong *)(unaff_RBP + -0x18) + 8) != '\x01')))) {
      FUN_000347b8(&DAT_00047cb0,0xb54,0,&DAT_00072148,unaff_RBP + 0x38);
    }
    else {
      HeroBeforeSaveNotify(0,0);
    }
    (**(code **)(DAT_00071fa8 + 0x48))(*(undefined8 *)(unaff_RBP + -0x30));
  }
  else {
    HeroBeforeSaveNotify(0);
  }
  *(undefined8 *)(unaff_RBP + -0x28) = 0;
  *(undefined8 *)(unaff_RBP + 0x38) = 0;
  lVar2 = FUN_00033ca0(u_PlatformLastLangCodes_00064418,&DAT_0004bb48,unaff_RBP + 0x38,
                       unaff_RBP + -0x28);
  if (lVar2 < 0) {
    pcVar3 = (char *)0x0;
  }
  else {
    pcVar3 = *(char **)(unaff_RBP + 0x38);
    if ((pcVar3 != (char *)0x0) && (*(longlong *)(unaff_RBP + -0x28) != 0)) {
      (**(code **)(DAT_00071f78 + 0x58))
                (u_PlatformLangCodes_00064458,&DAT_00047cd0,6,*(longlong *)(unaff_RBP + -0x28),
                 pcVar3);
    }
  }
  lVar2 = DAT_00071f78;
  *(undefined8 *)(unaff_RBP + -0x28) = 0;
  lVar2 = (**(code **)(lVar2 + 0x48))(u_PlatformLang_00064480,&DAT_00047cd0,0,unaff_RBP + -0x28,0);
  if (lVar2 != -0x7ffffffffffffffb) {
    lVar2 = 0;
    if ((pcVar3 == (char *)0x0) || (cVar1 = *pcVar3, cVar1 == '\0')) {
      lVar2 = 6;
      (**(code **)(DAT_00071f68 + 0x40))(4,6,unaff_RBP + 0x38);
      (**(code **)(DAT_00071f68 + 0x160))(*(undefined8 *)(unaff_RBP + 0x38),s_en_US_0006440c,6);
    }
    else {
      while ((cVar1 != ';' && (cVar1 != '\0'))) {
        lVar2 = lVar2 + 1;
        cVar1 = pcVar3[lVar2];
      }
      (**(code **)(DAT_00071f68 + 0x40))(4,lVar2 + 1,unaff_RBP + 0x38);
      (**(code **)(DAT_00071f68 + 0x160))(*(undefined8 *)(unaff_RBP + 0x38),pcVar3,lVar2);
      *(undefined1 *)(*(longlong *)(unaff_RBP + 0x38) + lVar2) = 0;
    }
    (**(code **)(DAT_00071f78 + 0x58))
              (u_PlatformLang_00064480,&DAT_00047cd0,7,lVar2,*(undefined8 *)(unaff_RBP + 0x38));
    (**(code **)(DAT_00071f68 + 0x48))(*(undefined8 *)(unaff_RBP + 0x38));
  }
  (**(code **)(DAT_00071f68 + 0x48))(pcVar3);
  return;
}

