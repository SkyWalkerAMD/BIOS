
void Original_RenderCleanup(uint param_1)

{
  longlong lVar1;
  short sVar2;
  int *piVar3;
  longlong *plVar4;
  longlong *plVar5;
  ulonglong uVar6;
  uint uVar7;
  ulonglong uVar9;
  ushort uVar10;
  longlong *plVar11;
  longlong *plVar12;
  ushort local_res8;
  longlong *local_res18;
  longlong *local_res20;
  ulonglong uVar8;
  
  uVar8 = 0;
  piVar3 = (int *)PTR_DAT_00094670;
  do {
    if (*piVar3 == 0) break;
    uVar7 = (int)uVar8 + 1;
    uVar8 = (ulonglong)uVar7;
    piVar3 = piVar3 + 6;
  } while (uVar7 < 6);
  uVar9 = (ulonglong)param_1;
  plVar4 = (longlong *)((ulonglong)*(uint *)(DAT_000baaf0 + 4 + uVar9 * 4) + DAT_000babc0);
  if ((*plVar4 != 0) && (*plVar4 != 0xffff)) {
    uVar6 = 0;
    local_res8 = 0;
    if (*(int *)((longlong)plVar4 + 0x1c) != 0) {
      do {
        local_res20 = (longlong *)0x0;
        plVar5 = (longlong *)
                 ((ulonglong)*(uint *)((longlong)plVar4 + uVar6 * 4 + 0x20) + DAT_000bab08);
        sVar2 = FUN_00033fa0(plVar5,&local_res20);
        if (sVar2 == -1) {
          uVar10 = 0;
          lVar1 = *(longlong *)
                   (*(longlong *)
                     (*(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar9 * 8) + 0x50) +
                   (uVar8 & 0xffff) * 8);
          plVar12 = *(longlong **)(lVar1 + 0x48);
          if (*(int *)(lVar1 + 0x3c) != 0) {
            do {
              if (plVar12 == (longlong *)0x0) break;
              if ((*(short *)(*plVar12 + 0x44) == *(short *)((longlong)plVar5 + 0x24)) &&
                 (*(short *)(*plVar12 + 0x46) == *(short *)((longlong)plVar5 + 0x26))) {
                local_res18 = (longlong *)0x0;
                FUN_00033fa0((longlong *)(*plVar12 + 0x20),&local_res18);
                if (((*(int *)(*plVar12 + 0x28) == 1) ||
                    (((local_res18 != (longlong *)0x0 && (*local_res20 == *local_res18)) &&
                     (local_res20[1] == local_res18[1])))) &&
                   ((plVar11 = (longlong *)(*plVar12 + 0x50), plVar11 != (longlong *)0x0 &&
                    (*plVar11 != 0)))) {
                  (**(code **)(DAT_000afbc8 + 0x48))();
                  *plVar11 = 0;
                }
              }
              uVar10 = uVar10 + 1;
              plVar12 = plVar12 + 1;
            } while ((uint)uVar10 <
                     *(uint *)(*(longlong *)
                                (*(longlong *)
                                  (*(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + uVar9 * 8) +
                                  0x50) + (uVar8 & 0xffff) * 8) + 0x3c));
            uVar6 = (ulonglong)local_res8;
          }
        }
        local_res8 = (short)uVar6 + 1;
        uVar6 = (ulonglong)local_res8;
      } while ((uint)local_res8 < *(uint *)((longlong)plVar4 + 0x1c));
    }
  }
  return;
}

