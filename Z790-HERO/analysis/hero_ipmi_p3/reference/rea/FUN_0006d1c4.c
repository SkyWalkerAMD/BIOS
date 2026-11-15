void FUN_0006d1c4(longlong param_1,longlong *param_2)
{
  longlong lVar1;
  longlong *plVar2;
  longlong lVar3;
  char cVar4;
  short sVar5;
  longlong *plVar6;
  longlong *plVar7;
  ulonglong uVar8;
  longlong *plVar9;
  longlong *plVar10;
  uint *puVar11;
  uint uVar12;
  ulonglong uVar13;
  longlong local_res8;
  longlong *local_res10;
  uVar13 = 0;
  puVar11 = DAT_001937e8;
  local_res8 = param_1;
  local_res10 = param_2;
  if (*DAT_001937e8 != 0) {
    do {
      plVar9 = (longlong *)((ulonglong)puVar11[uVar13 + 1] + DAT_001938e0);
      if ((plVar9 == (longlong *)0x0) || (*plVar9 != 0)) {
        lVar3 = plVar9[2];
        plVar6 = FUN_00067d50((short)lVar3);
        if ((plVar6 != (longlong *)0x0) &&
           ((lVar1 = *plVar6, *(short *)((longlong)plVar9 + 10) == *(short *)(lVar1 + 0x4a) &&
            (*(short *)(lVar1 + 0x48) == (short)lVar3)))) {
          *(longlong **)(lVar1 + 0x10) = plVar9;
          plVar6 = FUN_000b773c(plVar6);
          if (*(int *)(*plVar6 + 4) == 0x10011) {
            *(longlong **)(*plVar6 + 0x10) = plVar9;
          }
          local_res10 = (longlong *)plVar6[8];
          if ((local_res10 != (longlong *)0x0) &&
             (*(int *)((longlong)local_res10 + 0x2c) == 0x10011)) {
            for (plVar6 = (longlong *)local_res10[8]; plVar6 != (longlong *)0x0;
                plVar6 = (longlong *)plVar6[9]) {
              if (*(int *)(*plVar6 + 4) == 0x10018) {
                *(longlong **)(*(longlong *)(*plVar6 + 0x10) + 0x28) = plVar9;
                break;
              }
            }
            local_res10 = (longlong *)local_res10[9];
          }
          uVar8 = 0;
          plVar6 = local_res10;
          while( true ) {
            do {
              puVar11 = DAT_001937e8;
              if ((plVar6 == (longlong *)0x0) || (*(uint *)((longlong)plVar9 + 0x1c) <= (uint)uVar8)
                 ) goto LAB_0006d385;
            } while ((*(int *)(*plVar6 + 4) != 0x10012) ||
                    (plVar10 = (longlong *)
                               ((ulonglong)*(uint *)((longlong)plVar9 + uVar8 * 4 + 0x20) +
                               DAT_001937f8), plVar10 == (longlong *)0x0));
            cVar4 = FUN_0006d658((longlong)plVar10);
            puVar11 = DAT_001937e8;
            if (cVar4 != '\0') break;
            sVar5 = FUN_00028634(plVar10,&local_res8);
            if (sVar5 == -1) {
              FUN_0006c12c((longlong *)&local_res10,plVar10,local_res8,'\0');
            }
            else {
              *(longlong **)(*plVar6 + 0x10) = plVar10;
              plVar7 = (longlong *)plVar6[8];
              *(longlong **)(*plVar7 + 0x10) = plVar10;
              plVar2 = (longlong *)plVar7[9];
              if (plVar2 != (longlong *)0x0) {
                lVar3 = *plVar2;
                plVar7 = plVar2;
                if (*(int *)(lVar3 + 4) == 0x10005) {
                  *(longlong **)(*(longlong *)(lVar3 + 0x10) + 8) = plVar10;
                }
                else {
                  *(longlong **)(lVar3 + 0x10) = plVar10;
                }
              }
              if ((longlong *)plVar7[9] != (longlong *)0x0) {
                lVar3 = *(longlong *)plVar7[9];
                if (*(int *)(lVar3 + 4) == 0x10005) {
                  *(longlong **)(*(longlong *)(lVar3 + 0x10) + 8) = plVar10;
                }
                else {
                  *(longlong **)(lVar3 + 0x10) = plVar10;
                }
              }
              local_res10 = (longlong *)plVar6[9];
            }
            uVar8 = (ulonglong)((uint)uVar8 + 1);
            plVar6 = local_res10;
          }
        }
      }
LAB_0006d385:
      uVar12 = (int)uVar13 + 1;
      uVar13 = (ulonglong)uVar12;
    } while (uVar12 < *puVar11);
  }
  return;
}