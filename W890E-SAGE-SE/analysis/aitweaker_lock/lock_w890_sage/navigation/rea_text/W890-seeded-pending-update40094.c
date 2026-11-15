
longlong * Candidate_PendingUpdate(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  longlong lVar1;
  byte bVar2;
  longlong lVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong *plVar6;
  longlong *plVar7;
  uint *puVar8;
  
  plVar4 = (longlong *)0x0;
  bVar2 = 0;
  FUN_0003fed4(param_1,param_2,param_3);
  if ((DAT_000aff30 == (longlong *)0x0) ||
     (plVar5 = DAT_000aff30, plVar6 = plVar4, DAT_000aff30[1] == 0)) {
    plVar4 = (longlong *)0x800000000000000e;
  }
  else {
    do {
      plVar7 = (longlong *)plVar5[1];
      if (plVar7 == (longlong *)0x0) {
        DAT_000aff20 = 0;
        DAT_000aff23 = 1;
        return (longlong *)0x0;
      }
      if ((DAT_000baa68 == 0) || (DAT_000baa70 == (longlong *)0x0)) {
        lVar3 = plVar7[1];
        puVar8 = (uint *)plVar7[2];
      }
      else {
        do {
          if (DAT_000baa70 != (longlong *)0x0) {
            plVar6 = plVar4;
            do {
              if (*(longlong *)(DAT_000baa68 + (longlong)plVar6 * 8) == *plVar7) goto LAB_00040128;
              plVar6 = (longlong *)((longlong)plVar6 + 1);
            } while (plVar6 < DAT_000baa70);
          }
          plVar7 = (longlong *)plVar7[5];
        } while (plVar7 != (longlong *)0x0);
LAB_00040128:
        if (plVar7 == (longlong *)0x0) {
          DAT_000aff20 = 0;
          DAT_000aff23 = 1;
          return (longlong *)(~-(ulonglong)bVar2 & 0x800000000000000e);
        }
        lVar3 = plVar7[1];
        bVar2 = 1;
        puVar8 = (uint *)plVar7[2];
        plVar6 = plVar7;
      }
      lVar1 = *plVar7;
      if (lVar3 == 1) {
        if ((DAT_000aff22 != '\0') && (DAT_000aff40 != 0)) {
          FUN_00042b78();
        }
        FUN_0004244c(lVar1,puVar8);
        plVar5 = DAT_000aff30;
      }
      else if (lVar3 == 2) {
        if ((DAT_000aff38 == '\0') || (DAT_000aff40 != lVar1)) {
          if ((DAT_000aff22 != '\0') && (DAT_000aff40 != 0)) {
            FUN_00042b78();
          }
          lVar3 = FUN_000426cc(lVar1);
          if (lVar3 == 0) {
            DAT_000aff22 = '\x01';
            DAT_000aff40 = lVar1;
          }
          DAT_000aff38 = '\x01';
          plVar5 = DAT_000aff30;
        }
      }
      else if (lVar3 == 8) {
        FUN_000429c4(lVar1,puVar8);
        DAT_000aff22 = '\0';
        FUN_00042b78();
        DAT_000aff38 = '\0';
        plVar5 = DAT_000aff30;
      }
      if (((DAT_000baa68 == 0) || (DAT_000baa70 == (longlong *)0x0)) || (plVar6 == (longlong *)0x0))
      {
        lVar3 = plVar5[1];
        plVar7 = plVar6;
        if ((lVar3 != 0) && (*plVar5 != 0)) {
          if (lVar3 == plVar5[2]) {
            plVar5[2] = *(longlong *)(lVar3 + 0x28);
            plVar5 = DAT_000aff30;
          }
          plVar5[1] = *(longlong *)(lVar3 + 0x28);
          if (*(longlong *)(lVar3 + 0x20) != 0) {
            *(undefined8 *)(*(longlong *)(lVar3 + 0x20) + 0x28) = *(undefined8 *)(lVar3 + 0x28);
          }
          if (*(longlong *)(lVar3 + 0x28) != 0) {
            *(undefined8 *)(*(longlong *)(lVar3 + 0x28) + 0x20) = *(undefined8 *)(lVar3 + 0x20);
          }
          *DAT_000aff30 = *DAT_000aff30 + -1;
          (**(code **)(DAT_000afbc8 + 0x48))(lVar3);
          plVar5 = DAT_000aff30;
        }
      }
      else {
        plVar7 = plVar4;
        if ((plVar5 != (longlong *)0x0) && (*plVar5 != 0)) {
          if ((longlong *)plVar5[1] == plVar6) {
            if ((longlong *)plVar5[1] == (longlong *)plVar5[2]) {
              plVar5[2] = plVar6[5];
              plVar5 = DAT_000aff30;
            }
            plVar5[1] = plVar6[5];
            plVar5 = DAT_000aff30;
          }
          else if ((longlong *)plVar5[2] == plVar6) {
            plVar5[2] = plVar6[4];
            plVar5 = DAT_000aff30;
          }
          if (plVar6[4] != 0) {
            *(longlong *)(plVar6[4] + 0x28) = plVar6[5];
            plVar5 = DAT_000aff30;
          }
          if (plVar6[5] != 0) {
            *(longlong *)(plVar6[5] + 0x20) = plVar6[4];
            plVar5 = DAT_000aff30;
          }
          *plVar5 = *plVar5 + -1;
          (**(code **)(DAT_000afbc8 + 0x48))(plVar6);
          plVar5 = DAT_000aff30;
        }
      }
      plVar6 = plVar7;
    } while (plVar5 != (longlong *)0x0);
  }
  DAT_000aff20 = 0;
  DAT_000aff23 = 1;
  return plVar4;
}

