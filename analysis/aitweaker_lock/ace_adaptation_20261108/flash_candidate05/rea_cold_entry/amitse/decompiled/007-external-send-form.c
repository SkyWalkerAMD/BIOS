
longlong Candidate_ACE1904_external_send_form
                   (longlong param_1,undefined8 *param_2,undefined8 **param_3,undefined8 param_4,
                   undefined2 param_5,undefined8 param_6,undefined8 *param_7)

{
  ulonglong uVar1;
  bool bVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined1 uVar5;
  longlong lVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  undefined8 **ppuVar9;
  ulonglong *puVar10;
  undefined8 *puVar11;
  longlong unaff_RBX;
  undefined8 **ppuVar12;
  undefined8 **ppuVar13;
  ulonglong local_res10;
  uint local_58;
  uint local_54;
  longlong local_50;
  undefined8 local_48;
  longlong local_40;
  undefined8 *local_38;
  undefined8 *local_30;
  
  ppuVar12 = (undefined8 **)0x0;
  local_58 = 0;
  local_res10 = local_res10 & 0xffffffff00000000;
  local_40 = 0;
  local_50 = 0;
  local_48 = 0;
  local_54 = 0;
  puVar11 = param_2;
  ppuVar13 = param_3;
  FUN_00007fdc();
  uVar5 = DAT_00082659;
  if ((param_2 != (undefined8 *)0x0) && (param_3 != (undefined8 **)0x0)) {
    if ((DAT_00082748 != 0) || (bVar2 = true, DAT_00082690 != '\0')) {
      lVar6 = FUN_00021d8c(param_1);
      if (lVar6 < 0) {
LAB_00020ff2:
        lVar6 = (**(code **)(DAT_000824c8 + 0x140))(&DAT_0006a780,0,&local_40);
        if (lVar6 != 0) {
          return unaff_RBX;
        }
        (**(code **)(local_40 + 0x20))
                  (u_SendForm_Unsupported_0007c2b8,u_SendForm_Not_suppored_Nestedly_o_0007c240,1,0);
        return unaff_RBX;
      }
      lVar6 = FUN_00044b58(param_1);
      if (lVar6 < 0) {
        do {
          local_res10 = DAT_000921f8;
          if (DAT_000921f8 != 0) {
            DAT_000921f8 = *(ulonglong *)(DAT_000921f8 + 0x191);
          }
          FUN_00005958((longlong *)&local_res10);
        } while (local_res10 != 0);
        goto LAB_00020ff2;
      }
      FUN_0000ebf4();
      FUN_00010144();
      FUN_00036148();
      bVar2 = false;
    }
    if (DAT_00092b08 == 0) {
      lVar6 = FUN_00044b58(param_1);
      if (lVar6 < 0) {
        return unaff_RBX;
      }
      FUN_0000ebf4();
      FUN_00010144();
    }
    if (DAT_00082638 == (undefined8 *)0x0) {
      FUN_00007a78(param_1,puVar11);
      FUN_00007dd4(param_1);
    }
    puVar11 = (undefined8 *)((longlong)param_3 << 3);
    DAT_000921e8 = FUN_0003eea8(param_1,(ulonglong)puVar11);
    DAT_00082808 = param_5;
    DAT_000921f0 = 0;
    DAT_000827f8 = param_4;
    if (param_3 != (undefined8 **)0x0) {
      do {
        ppuVar9 = (undefined8 **)param_2[(longlong)ppuVar12];
        ppuVar13 = &local_38;
        local_38 = (undefined8 *)0x0;
        local_30 = FUN_00029dcc(ppuVar9,puVar11,(ulonglong *)ppuVar13);
        if (local_30 != (undefined8 *)0x0) {
          puVar11 = (undefined8 *)param_2[(longlong)ppuVar12];
          DAT_000921e8[DAT_000921f0] = puVar11;
          ppuVar9 = &local_30;
          FUN_00005958((longlong *)ppuVar9);
          DAT_000921f0 = DAT_000921f0 + 1;
        }
        ppuVar12 = (undefined8 **)((longlong)ppuVar12 + 1);
      } while (ppuVar12 < param_3);
      if (DAT_000921f0 != 0) {
        DAT_000921e0 = 0;
        if (DAT_00082650 == 0) {
          FUN_000109dc();
          FUN_00010a94(ppuVar9,0);
        }
        (**(code **)(DAT_000824c8 + 0x18))(0x1f);
        (**(code **)(DAT_000824c8 + 0x20))(4);
        FUN_00008564();
        FUN_00033874();
        if (DAT_00082638 != (undefined8 *)0x0) {
          (*(code *)*DAT_00082638)(DAT_00082638,&local_54,0,0);
        }
        if ((DAT_000824c0 != (ulonglong *)0x0) &&
           (puVar11 = (undefined8 *)DAT_000824c0[6], puVar11 != (undefined8 *)0x0)) {
          (*(code *)*puVar11)(puVar11,0);
        }
        uVar5 = DAT_00082659;
        if (DAT_00082688 != 0) {
          FUN_0000d984(&DAT_00082688);
        }
        uVar4 = DAT_0006abf0;
        uVar3 = DAT_0006abe8;
        DAT_00082839 = 0;
        if (DAT_00082668 != (undefined8 **)0x0) {
          local_58 = *(uint *)((longlong)DAT_00082668[3] + 4);
        }
        if ((DAT_000824c0 != (ulonglong *)0x0) && (DAT_000824c0[8] != 0)) {
          local_res10 = CONCAT44(local_res10._4_4_,
                                 *(undefined4 *)(*(longlong *)(DAT_000824c0[8] + 0x48) + 4));
        }
        puVar10 = DAT_000824c0;
        FUN_00006dd8(DAT_000824c0);
        lVar6 = DAT_00092af0;
        if (bVar2) {
          DAT_00092af0 = 0;
          local_50 = lVar6;
          local_48 = DAT_00082628;
          if (DAT_0008270a != '\0') {
            puVar10 = (ulonglong *)(DAT_00091028 + 0x28);
            FUN_0000d984((longlong *)puVar10);
          }
        }
        puVar7 = FUN_0003eea8(puVar10,0xb71b04);
        puVar11 = (undefined8 *)0xb71b04;
        local_30 = puVar7;
        puVar8 = FUN_0003eea8(puVar10,0xb71b04);
        local_38 = puVar8;
        if ((puVar7 != (undefined8 *)0x0) &&
           (puVar11 = DAT_00092b28, DAT_00092b28 != (undefined8 *)0x0)) {
          (**(code **)(DAT_000824c8 + 0x160))(puVar7,DAT_00092b28,0xb71b04);
        }
        if ((puVar8 != (undefined8 *)0x0) &&
           (puVar11 = DAT_00092b38, DAT_00092b38 != (undefined8 *)0x0)) {
          (**(code **)(DAT_000824c8 + 0x160))(puVar8,DAT_00092b38,0xb71b04);
        }
        FUN_000040bc();
        Candidate_ACE1904_browser_loop();
        DAT_0006abe8 = uVar3;
        DAT_0006abf0 = uVar4;
        if (((DAT_000824c0 != (ulonglong *)0x0) && (uVar1 = DAT_000824c0[8], uVar1 != 0)) &&
           ((int)local_res10 != *(int *)(*(longlong *)(uVar1 + 0x48) + 4))) {
          puVar11 = (undefined8 *)(local_res10 & 0xffffffff);
          (**(code **)(uVar1 + 0x20))(uVar1);
        }
        if ((puVar7 != (undefined8 *)0x0) && (DAT_00092b28 != (undefined8 *)0x0)) {
          (**(code **)(DAT_000824c8 + 0x160))();
          FUN_00005958((longlong *)&local_30);
          puVar11 = puVar7;
        }
        if ((puVar8 != (undefined8 *)0x0) && (DAT_00092b38 != (undefined8 *)0x0)) {
          puVar11 = (undefined8 *)0xb71b04;
          FUN_00000360(DAT_00092b38,0xb71b04,0);
          FUN_00005958((longlong *)&local_38);
        }
        ppuVar13 = DAT_00082668;
        if ((DAT_00082668 != (undefined8 **)0x0) &&
           (puVar11 = (undefined8 *)(ulonglong)local_58,
           local_58 != *(uint *)((longlong)DAT_00082668[3] + 4))) {
          (*(code *)DAT_00082668[1])(DAT_00082668);
        }
        if (bVar2) {
          if (local_50 != 0) {
            DAT_00092af0 = local_50;
          }
          DAT_00082628 = local_48;
          if (DAT_0008270a != '\0') {
            FUN_0004a0f0();
          }
          if (DAT_00082638 != (undefined8 *)0x0) {
            puVar11 = (undefined8 *)(ulonglong)local_54;
            (*(code *)DAT_00082638[1])(DAT_00082638);
          }
        }
        else {
          FUN_00022d20();
        }
        FUN_00006e8c();
        if ((!bVar2) && (DAT_00092af0 != 0)) {
          FUN_00005958(&DAT_00092af0);
        }
        goto LAB_00021405;
      }
    }
    FUN_00005958((longlong *)&DAT_000921e8);
    uVar5 = DAT_00082659;
  }
LAB_00021405:
  DAT_00082659 = uVar5;
  if (DAT_00082740 != '\0') {
    if (DAT_000921f8 == 0) {
      FUN_00005ab8(0xffff001e,&LAB_00006370);
      ppuVar13 = (undefined8 **)0x0;
      puVar11 = (undefined8 *)0x0;
      (**(code **)(DAT_000824d8 + 0x68))(0,0,0,0);
    }
    else {
      *(undefined8 *)(DAT_000921f8 + 0x191) = *(undefined8 *)(DAT_000921f8 + 0x191);
    }
  }
  if (DAT_00082838 != '\0') {
    if (param_7 != (undefined8 *)0x0) {
      *param_7 = 1;
    }
    DAT_00082838 = '\0';
  }
  if (DAT_00082898 != '\0') {
    FUN_000298c8();
  }
  DAT_00082898 = 0;
  FUN_000109dc();
  puVar7 = &DAT_000921e8;
  FUN_00005958((longlong *)&DAT_000921e8);
  DAT_000921e8 = (undefined8 *)0x0;
  DAT_00082808 = 0;
  DAT_000921f0 = 0;
  DAT_000921e0 = 0;
  lVar6 = FUN_0002224c();
  if (((lVar6 == 0) && (FUN_00036098(), DAT_00082970 != '\0')) && (DAT_00082899 == '\0')) {
    DAT_00082899 = 1;
    FUN_00029b34(puVar7,puVar11,ppuVar13);
    DAT_00082899 = '\0';
  }
  return unaff_RBX;
}

