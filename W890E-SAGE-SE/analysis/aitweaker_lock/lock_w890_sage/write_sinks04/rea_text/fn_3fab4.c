
undefined8 FUN_0003fab4(longlong param_1,longlong param_2,undefined8 param_3,longlong *param_4)

{
  longlong lVar1;
  undefined8 uVar2;
  longlong *plVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong lVar6;
  longlong *plVar7;
  longlong lVar8;
  longlong lVar9;
  
  lVar9 = 0;
  lVar8 = 0;
  lVar6 = 0;
  uVar2 = 0x800000000000000e;
  if (DAT_000aff30 == (longlong *)0x0) {
    uVar2 = 0x8000000000000002;
  }
  else {
    if (param_4 != (longlong *)0x0) {
      lVar9 = param_4[4];
      lVar8 = param_4[5];
    }
    if ((param_2 == 0) && (param_2 = 0, param_4 != (longlong *)0x0)) {
      param_2 = *param_4;
      lVar6 = param_4[1];
    }
    plVar5 = (longlong *)DAT_000aff30[1];
    plVar7 = DAT_000aff30;
LAB_0003fb30:
    do {
      plVar4 = plVar5;
      if (plVar4 == (longlong *)0x0) goto LAB_0003fcd3;
      plVar5 = (longlong *)plVar4[5];
      if (param_1 != 0) {
        if (plVar4 == param_4) goto LAB_0003fb30;
        if (param_1 == 1) {
          if ((plVar4[1] == 1) || (*plVar4 != param_2)) goto LAB_0003fb30;
          if ((plVar7 != (longlong *)0x0) && (*plVar7 != 0)) {
            if ((longlong *)plVar7[1] == plVar4) {
              plVar3 = plVar5;
              if ((longlong *)plVar7[1] == (longlong *)plVar7[2]) {
LAB_0003fbcc:
                plVar7[2] = (longlong)plVar5;
                plVar7 = DAT_000aff30;
                goto LAB_0003fbd7;
              }
              goto LAB_0003fbdb;
            }
LAB_0003fc12:
            if ((longlong *)plVar7[2] == plVar4) {
              plVar7[2] = plVar4[4];
              plVar7 = DAT_000aff30;
            }
LAB_0003fc27:
            if (plVar4[4] != 0) {
              *(longlong *)(plVar4[4] + 0x28) = plVar4[5];
              plVar7 = DAT_000aff30;
            }
            if (plVar4[5] != 0) {
              *(longlong *)(plVar4[5] + 0x20) = plVar4[4];
              plVar7 = DAT_000aff30;
            }
            lVar1 = DAT_000afbc8;
            *plVar7 = *plVar7 + -1;
            (**(code **)(lVar1 + 0x48))();
            plVar7 = DAT_000aff30;
          }
        }
        else {
          if (((param_1 != 3) || (*plVar4 != param_2)) || (plVar4[1] != lVar6)) goto LAB_0003fb30;
          if ((plVar7 != (longlong *)0x0) && (*plVar7 != 0)) {
            if ((longlong *)plVar7[1] != plVar4) goto LAB_0003fc12;
            if ((longlong *)plVar7[1] == (longlong *)plVar7[2]) goto LAB_0003fbcc;
LAB_0003fbd7:
            plVar3 = (longlong *)plVar4[5];
LAB_0003fbdb:
            plVar7[1] = (longlong)plVar3;
            plVar7 = DAT_000aff30;
            goto LAB_0003fc27;
          }
        }
        uVar2 = 0;
        goto LAB_0003fb30;
      }
    } while (plVar4 != param_4);
    if ((plVar7 != (longlong *)0x0) && (*plVar7 != 0)) {
      if ((longlong *)plVar7[1] == plVar4) {
        if ((longlong *)plVar7[1] == (longlong *)plVar7[2]) {
          plVar7[2] = (longlong)plVar5;
          plVar5 = (longlong *)plVar4[5];
          plVar7 = DAT_000aff30;
        }
        plVar7[1] = (longlong)plVar5;
        plVar7 = DAT_000aff30;
      }
      else if ((longlong *)plVar7[2] == plVar4) {
        plVar7[2] = plVar4[4];
        plVar7 = DAT_000aff30;
      }
      if (plVar4[4] != 0) {
        *(longlong *)(plVar4[4] + 0x28) = plVar4[5];
        plVar7 = DAT_000aff30;
      }
      if (plVar4[5] != 0) {
        *(longlong *)(plVar4[5] + 0x20) = plVar4[4];
        plVar7 = DAT_000aff30;
      }
      lVar6 = DAT_000afbc8;
      *plVar7 = *plVar7 + -1;
      (**(code **)(lVar6 + 0x48))();
      plVar7 = DAT_000aff30;
    }
    uVar2 = 0;
LAB_0003fcd3:
    plVar5 = (longlong *)plVar7[1];
    if (param_4 != (longlong *)0x0) {
      for (; plVar5 != (longlong *)0x0; plVar5 = (longlong *)plVar5[5]) {
        if (param_4 == plVar5) {
          return uVar2;
        }
      }
      param_4[4] = lVar9;
      param_4[5] = lVar8;
    }
  }
  return uVar2;
}

