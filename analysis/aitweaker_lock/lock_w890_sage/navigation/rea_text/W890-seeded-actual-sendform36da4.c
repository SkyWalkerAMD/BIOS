
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong Observed_FormBrowser2_SendForm
                   (longlong param_1,undefined8 *param_2,ulonglong *param_3,undefined8 param_4,
                   undefined2 param_5,undefined8 param_6,undefined8 *param_7)

{
  bool bVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined1 uVar4;
  longlong lVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  longlong *plVar9;
  undefined8 *puVar10;
  longlong unaff_RBX;
  ulonglong *puVar11;
  uint uVar12;
  ulonglong *puVar13;
  uint local_res10;
  uint local_58 [2];
  longlong local_50;
  undefined8 local_48;
  longlong local_40 [3];
  
  puVar11 = (ulonglong *)0x0;
  uVar12 = 0;
  local_res10 = 0;
  local_40[0] = 0;
  local_50 = 0;
  local_48 = 0;
  local_58[0] = 0;
  puVar10 = param_2;
  puVar13 = param_3;
  FUN_00012204();
  uVar4 = DAT_000afce1;
  if ((param_2 != (undefined8 *)0x0) && (param_3 != (ulonglong *)0x0)) {
    if ((DAT_000afdd0 != 0) || (bVar1 = true, DAT_000afd18 != '\0')) {
      lVar5 = FUN_00037c68(param_1);
      if (lVar5 < 0) {
LAB_00036e58:
        lVar5 = (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093628,0,local_40);
        if (lVar5 != 0) {
          return unaff_RBX;
        }
        (**(code **)(local_40[0] + 0x20))
                  (u_SendForm_Unsupported_000a9418,u_SendForm_Not_suppored_Nestedly_o_000a93a0,1,0);
        return unaff_RBX;
      }
      lVar5 = FUN_0005efac(param_1);
      if (lVar5 < 0) {
        if (DAT_000baa78 != 0) {
          DAT_000baa78 = *(longlong *)(DAT_000baa78 + 0x191);
          (**(code **)(DAT_000afbc8 + 0x48))();
        }
        goto LAB_00036e58;
      }
      FUN_00019cf8();
      FUN_0001b7dc();
      FUN_0004e4f4();
      bVar1 = false;
    }
    if (DAT_000babc0 == 0) {
      lVar5 = FUN_0005efac(param_1);
      if (lVar5 < 0) {
        return unaff_RBX;
      }
      FUN_00019cf8();
      FUN_0001b7dc();
    }
    if (DAT_000afcc0 == (undefined8 *)0x0) {
      FUN_00011e18(param_1,puVar10);
      FUN_00012174(param_1);
    }
    puVar10 = (undefined8 *)((longlong)param_3 * 8);
    DAT_000baa68 = FUN_00059b50(param_1,(ulonglong)puVar10);
    DAT_000afe90 = param_5;
    DAT_000baa70 = 0;
    DAT_000afe80 = param_4;
    if (param_3 != (ulonglong *)0x0) {
      do {
        puVar7 = (undefined8 *)param_2[(longlong)puVar11];
        puVar13 = (ulonglong *)(local_40 + 1);
        local_40[1] = 0;
        puVar6 = FUN_00040434(puVar7,puVar10,puVar13);
        puVar8 = DAT_000baa68;
        if (puVar6 != (undefined8 *)0x0) {
          puVar13 = (ulonglong *)param_2[(longlong)puVar11];
          DAT_000baa68[DAT_000baa70] = puVar13;
          (**(code **)(DAT_000afbc8 + 0x48))();
          DAT_000baa70 = DAT_000baa70 + 1;
          puVar7 = puVar6;
          puVar10 = puVar8;
        }
        puVar11 = (ulonglong *)((longlong)puVar11 + 1);
      } while (puVar11 < param_3);
      if (DAT_000baa70 != 0) {
        DAT_000baa60 = 0;
        if (DAT_000afcd8 == 0) {
          FUN_0001c078();
          FUN_0001c17c(puVar7,0);
        }
        (**(code **)(DAT_000afbc8 + 0x18))(0x1f);
        (**(code **)(DAT_000afbc8 + 0x20))(4);
        FUN_00012790();
        FUN_0004b608();
        if (DAT_000afcc0 != (undefined8 *)0x0) {
          (*(code *)*DAT_000afcc0)(DAT_000afcc0,local_58,0,0);
        }
        if ((DAT_000afbc0 != (longlong *)0x0) &&
           (puVar10 = (undefined8 *)DAT_000afbc0[6], puVar10 != (undefined8 *)0x0)) {
          (*(code *)*puVar10)(puVar10,0);
        }
        uVar4 = DAT_000afce1;
        if (DAT_000afd10 != 0) {
          FUN_000187c0(&DAT_000afd10);
        }
        uVar3 = DAT_00093a70;
        uVar2 = DAT_00093a68;
        DAT_000afec1 = 0;
        if (DAT_000afcf0 != (ulonglong *)0x0) {
          local_res10 = *(uint *)(DAT_000afcf0[3] + 4);
        }
        if ((DAT_000afbc0 != (longlong *)0x0) && (DAT_000afbc0[8] != 0)) {
          uVar12 = *(uint *)(*(longlong *)(DAT_000afbc0[8] + 0x48) + 4);
        }
        plVar9 = DAT_000afbc0;
        FUN_00011028();
        lVar5 = DAT_000baba8;
        if (bVar1) {
          DAT_000baba8 = 0;
          local_50 = lVar5;
          local_48 = _DAT_000afcb0;
          if (DAT_000afd92 != '\0') {
            plVar9 = (longlong *)(DAT_000ba5a8 + 0x28);
            FUN_000187c0(plVar9);
          }
        }
        puVar7 = FUN_00059b50(plVar9,0xb71b04);
        puVar10 = (undefined8 *)0xb71b04;
        puVar8 = FUN_00059b50(plVar9,0xb71b04);
        if ((puVar7 != (undefined8 *)0x0) &&
           (puVar10 = DAT_000babe0, DAT_000babe0 != (undefined8 *)0x0)) {
          (**(code **)(DAT_000afbc8 + 0x160))(puVar7,DAT_000babe0,0xb71b04);
        }
        if ((puVar8 != (undefined8 *)0x0) &&
           (puVar10 = DAT_000babf0, DAT_000babf0 != (undefined8 *)0x0)) {
          (**(code **)(DAT_000afbc8 + 0x160))(puVar8,DAT_000babf0,0xb71b04);
        }
        FUN_0000ce50();
        Observed_BrowserLoop();
        DAT_00093a68 = uVar2;
        DAT_00093a70 = uVar3;
        if (((DAT_000afbc0 != (longlong *)0x0) && (lVar5 = DAT_000afbc0[8], lVar5 != 0)) &&
           (uVar12 != *(uint *)(*(longlong *)(lVar5 + 0x48) + 4))) {
          puVar10 = (undefined8 *)(ulonglong)uVar12;
          (**(code **)(lVar5 + 0x20))(lVar5);
        }
        if ((puVar7 != (undefined8 *)0x0) && (DAT_000babe0 != (undefined8 *)0x0)) {
          puVar10 = puVar7;
          (**(code **)(DAT_000afbc8 + 0x160))();
          (**(code **)(DAT_000afbc8 + 0x48))(puVar7);
        }
        if ((puVar8 != (undefined8 *)0x0) && (DAT_000babf0 != (undefined8 *)0x0)) {
          puVar10 = (undefined8 *)0xb71b04;
          FUN_00001600((undefined1 *)DAT_000babf0,0xb71b04,0);
          (**(code **)(DAT_000afbc8 + 0x48))(puVar8);
        }
        puVar13 = DAT_000afcf0;
        if ((DAT_000afcf0 != (ulonglong *)0x0) &&
           (puVar10 = (undefined8 *)(ulonglong)local_res10,
           local_res10 != *(uint *)(DAT_000afcf0[3] + 4))) {
          (*(code *)DAT_000afcf0[1])(DAT_000afcf0);
        }
        if (bVar1) {
          if (local_50 != 0) {
            DAT_000baba8 = local_50;
          }
          _DAT_000afcb0 = local_48;
          if (DAT_000afd92 != '\0') {
            FUN_00065690();
          }
          if (DAT_000afcc0 != (undefined8 *)0x0) {
            puVar10 = (undefined8 *)(ulonglong)local_58[0];
            (*(code *)DAT_000afcc0[1])(DAT_000afcc0);
          }
          FUN_000110dc();
        }
        else {
          FUN_00038c28();
          FUN_000110dc();
          if (DAT_000baba8 != 0) {
            (**(code **)(DAT_000afbc8 + 0x48))();
            DAT_000baba8 = 0;
          }
        }
        goto LAB_000372a3;
      }
    }
    uVar4 = DAT_000afce1;
    if (DAT_000baa68 != (undefined8 *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x48))(DAT_000baa68);
      DAT_000baa68 = (undefined8 *)0x0;
      uVar4 = DAT_000afce1;
    }
  }
LAB_000372a3:
  DAT_000afce1 = uVar4;
  if ((DAT_000afdc8 != '\0') && (DAT_000baa78 == 0)) {
    FUN_0000fd18(0xffff001e,&LAB_000069ec);
    puVar10 = (undefined8 *)0x0;
    puVar13 = (ulonglong *)0x0;
    (**(code **)(DAT_000afbd8 + 0x68))(1,0,0,0);
  }
  if (DAT_000afec0 != '\0') {
    if (param_7 != (undefined8 *)0x0) {
      *param_7 = 1;
    }
    DAT_000afec0 = '\0';
  }
  if (DAT_000aff20 != '\0') {
    FUN_0003fd14();
  }
  DAT_000aff20 = 0;
  FUN_0001c078();
  puVar7 = DAT_000baa68;
  if (DAT_000baa68 != (undefined8 *)0x0) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    puVar7 = DAT_000baa68;
  }
  DAT_000baa68 = (undefined8 *)0x0;
  DAT_000afe90 = 0;
  DAT_000baa70 = 0;
  DAT_000baa60 = 0;
  lVar5 = FUN_0003809c();
  if (((lVar5 == 0) && (FUN_0004e444(), DAT_000afff8 != '\0')) && (DAT_000aff21 == '\0')) {
    DAT_000aff21 = 1;
    Candidate_PendingUpdate(puVar7,puVar10,puVar13);
    DAT_000aff21 = '\0';
  }
  return unaff_RBX;
}

