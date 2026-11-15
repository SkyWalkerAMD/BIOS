
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00013dd8(undefined8 param_1,byte param_2)

{
  char cVar1;
  longlong lVar2;
  ulonglong uVar3;
  char *pcVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  longlong lVar7;
  char cVar8;
  undefined4 *puVar9;
  wchar_t *pwVar10;
  char *pcVar11;
  longlong *plVar12;
  ulonglong uVar13;
  char *pcVar14;
  undefined8 *puVar15;
  undefined4 uVar16;
  char *pcVar17;
  ulonglong uVar18;
  longlong lVar19;
  undefined4 extraout_XMM0_Da;
  undefined4 extraout_XMM0_Da_00;
  undefined4 extraout_XMM0_Da_01;
  undefined4 extraout_XMM0_Da_02;
  longlong local_res18;
  longlong local_res20;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 uStack_c4;
  undefined4 uStack_c0;
  undefined4 uStack_bc;
  undefined4 local_b8;
  undefined4 uStack_b4;
  undefined4 uStack_b0;
  undefined4 uStack_ac;
  char *local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 uStack_80;
  undefined8 local_78;
  undefined4 local_70;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined8 local_58;
  undefined4 local_50;
  
  local_c8 = 0xec87d643;
  uVar18 = 0;
  local_78 = 0;
  local_70 = 0;
  local_58 = 0;
  puVar9 = &local_d8;
  local_50 = 0;
  local_res20 = 0;
  local_90 = 0;
  local_88 = 0;
  uStack_80 = 0;
  local_a0 = 0;
  local_68 = 0;
  uStack_60 = 0;
  local_a8 = (char *)0x0;
  uStack_c4 = 0x4bb5eba4;
  uStack_c0 = 0x3e3fe5a1;
  uStack_bc = 0xa90db236;
  local_b8 = 0x5a105a0;
  uStack_b4 = 0x5a305a2;
  uStack_b0 = 0x5a505a4;
  uStack_ac = 0x5a705a6;
  local_d8 = 0x575ad44e;
  local_d4 = 0x4a79a6f1;
  local_d0 = 0x418a79f;
  local_cc = 0xa38ed8e4;
  lVar2 = FUN_00013154(puVar9,&local_a0,&local_a8);
  pcVar11 = local_a8;
  if (lVar2 < 0) {
    return;
  }
  uVar13 = 0;
  if ((local_a8 != (char *)0x0) &&
     (uVar6 = CONCAT71((int7)((ulonglong)puVar9 >> 8),*local_a8), pcVar17 = local_a8,
     *local_a8 != '\0')) {
    do {
      uVar3 = uVar13 + 1;
      if ((char)uVar6 != ';') {
        uVar3 = uVar13;
      }
      cVar1 = pcVar17[1];
      uVar6 = CONCAT71((int7)((ulonglong)uVar6 >> 8),cVar1);
      pcVar17 = pcVar17 + 1;
      uVar13 = uVar3;
    } while (cVar1 != '\0');
    if (((uVar3 != 0) && (lVar2 = FUN_0001e280(uVar6,uVar3 * 0x90), lVar2 != 0)) &&
       (*pcVar11 != '\0')) {
      lVar19 = lVar2 + 0x86;
      do {
        if (uVar3 <= uVar18) break;
        cVar1 = *pcVar11;
        local_res18 = 0;
        pcVar17 = pcVar11;
        do {
          while ((cVar1 != ',' && (cVar1 != ';'))) {
            if (cVar1 == '\0') goto LAB_000140b6;
            pcVar11 = pcVar11 + 1;
            cVar1 = *pcVar11;
          }
          if (cVar1 == '\0') goto LAB_000140b6;
          *pcVar11 = '\0';
          pcVar11 = pcVar11 + 1;
          if (local_res18 == 0) {
            lVar7 = lVar19 + -0x86;
            uVar16 = 0x32;
LAB_00014029:
            FUN_000112a8(pcVar17,lVar7,uVar16);
          }
          else if (local_res18 == 1) {
            lVar7 = 0;
            if (*pcVar17 != '\0') {
              do {
                lVar7 = lVar7 + 1;
              } while (pcVar17[lVar7] != '\0');
              if (lVar7 != 0) {
                FUN_0001131c(pcVar17);
              }
            }
          }
          else if (local_res18 == 2) {
            FUN_000112a8(pcVar17,lVar19 + -0x3e,0x3c);
            for (; cVar8 = *pcVar17, cVar8 != '\0'; pcVar17 = pcVar17 + 1) {
              pcVar4 = &DAT_000429a4;
              pcVar14 = pcVar17;
              if (cVar8 == '[') {
                do {
                  if (cVar8 == '\0') break;
                  pcVar14 = pcVar14 + 1;
                  pcVar4 = pcVar4 + 1;
                  cVar8 = *pcVar14;
                } while (cVar8 == *pcVar4);
                if (*pcVar4 == '\0') {
                  if (pcVar17 != (char *)0x0) {
                    pcVar17 = pcVar17 + 1;
                    pcVar14 = (char *)FUN_0001f7b4(pcVar17,&DAT_000429a8);
                    if ((pcVar14 != (char *)0x0) && (pcVar17 != pcVar14)) {
                      FUN_000200e4(pcVar17);
                    }
                  }
                  break;
                }
              }
              if (*pcVar14 == '\0') break;
            }
          }
          else if (local_res18 == 3) {
            uVar16 = 10;
            lVar7 = lVar19;
            goto LAB_00014029;
          }
          local_res18 = local_res18 + 1;
        } while ((cVar1 != ';') && (cVar1 = *pcVar11, pcVar17 = pcVar11, cVar1 != '\0'));
        if (local_res18 != 4) goto LAB_00014069;
        uVar18 = uVar18 + 1;
        lVar19 = lVar19 + 0x90;
      } while (*pcVar11 != '\0');
    }
  }
LAB_000140c7:
  _DAT_0004b168 = (uint)*(ushort *)((longlong)DAT_00048288 + 0x1c) << 0x10;
  _DAT_0004b170 = DAT_00048280;
  _DAT_0004b178 = *(undefined2 *)((longlong)DAT_00048288 + 0x1e);
  FUN_0001e3ac(&local_88,0x1c,u_ProfileName_d_000429d0,param_2);
  local_98 = 0x1c;
  lVar2 = (**(code **)(DAT_000483e8 + 0x48))(&local_88,&DAT_00030030,0,&local_98,&local_68);
  if (lVar2 < 0) {
    _DAT_0004b168 = 0x59f1800;
    _DAT_0004b178 = *(undefined2 *)((longlong)&uStack_bc + (longlong)(int)(uint)param_2 * 2 + 2);
    _DAT_0004b170 = param_1;
    (**(code **)(DAT_00048290 + 0x18))(&DAT_0004b168,1);
    return;
  }
  cVar1 = (**(code **)(DAT_00048290 + 0x18))(&DAT_0004b168,3,0);
  if (cVar1 != '\0') {
    return;
  }
  plVar12 = (longlong *)(((ulonglong)(uint)param_2 + 0x2e) * 0x10 + *DAT_00048288);
  if (plVar12[1] == 0) {
    return;
  }
  if (*plVar12 == 0) {
    return;
  }
  local_b8 = local_c8;
  uStack_b4 = uStack_c4;
  uStack_b0 = uStack_c0;
  uStack_ac = uStack_bc;
  lVar2 = (**(code **)(DAT_00048290 + 0x20))(u_Setup_00041658,&local_b8,&local_res20,&local_90);
  if (lVar2 < 0) {
    return;
  }
  lVar2 = FUN_0001e280(extraout_XMM0_Da,0x10);
  lVar19 = FUN_0001333c(*plVar12,plVar12[1],lVar2,lVar2 + 8);
  if (lVar19 < 0) {
    return;
  }
  if (*(char *)(local_res20 + 0x177) == '\0') {
    puVar5 = (undefined8 *)FUN_0001e280(local_res20,0x10);
    puVar15 = puVar5 + 1;
    lVar19 = (**(code **)(DAT_000483e8 + 0x48))
                       (u_ProfileMask1_00042a80,&DAT_00030030,0,puVar15,*puVar5);
    uVar16 = extraout_XMM0_Da_00;
    if (lVar19 != -0x7ffffffffffffffb) goto LAB_0001434a;
    uVar6 = FUN_0001e280(extraout_XMM0_Da_00,*puVar15);
    pwVar10 = u_ProfileMask1_00042a80;
  }
  else if (*(char *)(local_res20 + 0x177) == '\x01') {
    puVar5 = (undefined8 *)FUN_0001e280(local_res20,0x10);
    puVar15 = puVar5 + 1;
    lVar19 = (**(code **)(DAT_000483e8 + 0x48))
                       (u_ProfileMask2_00042aa0,&DAT_00030030,0,puVar15,*puVar5);
    uVar16 = extraout_XMM0_Da_01;
    if (lVar19 != -0x7ffffffffffffffb) goto LAB_0001434a;
    uVar6 = FUN_0001e280(extraout_XMM0_Da_01,*puVar15);
    pwVar10 = u_ProfileMask2_00042aa0;
  }
  else {
    puVar5 = (undefined8 *)FUN_0001e280(local_res20,0x10);
    puVar15 = puVar5 + 1;
    lVar19 = (**(code **)(DAT_000483e8 + 0x48))
                       (u_ProfileMask3_00042ac0,&DAT_00030030,0,puVar15,*puVar5);
    uVar16 = extraout_XMM0_Da_02;
    if (lVar19 != -0x7ffffffffffffffb) goto LAB_0001434a;
    uVar6 = FUN_0001e280(extraout_XMM0_Da_02,*puVar15);
    pwVar10 = u_ProfileMask3_00042ac0;
  }
  *puVar5 = uVar6;
  uVar16 = (**(code **)(DAT_000483e8 + 0x48))(pwVar10,&DAT_00030030,0,puVar15,uVar6);
LAB_0001434a:
  lVar19 = FUN_0001e280(uVar16,0x10);
  lVar7 = FUN_0001333c(*puVar5,*puVar15,lVar19,lVar19 + 8);
  if (-1 < lVar7) {
    lVar2 = FUN_000122a0(lVar2,lVar19);
    if (-1 < lVar2) {
      *(byte *)(local_res20 + 0x175) = param_2;
    }
    FUN_000125d0(DAT_00048280);
  }
  return;
LAB_00014069:
  if (uVar18 != 0) {
    plVar12 = (longlong *)(lVar2 + 0x40);
    do {
      if (*plVar12 != 0) {
        uVar13 = 0;
        if (plVar12[-1] != 0) {
          lVar19 = 0;
          do {
            if (*(longlong *)(lVar19 + *plVar12) != 0) {
              (**(code **)(DAT_000483d8 + 0x48))();
            }
            uVar13 = uVar13 + 1;
            lVar19 = lVar19 + 0x10;
          } while (uVar13 < (ulonglong)plVar12[-1]);
        }
        *plVar12 = 0;
      }
      plVar12 = plVar12 + 0x12;
      uVar18 = uVar18 - 1;
    } while (uVar18 != 0);
  }
LAB_000140b6:
  (**(code **)(DAT_000483d8 + 0x48))(lVar2);
  goto LAB_000140c7;
}

