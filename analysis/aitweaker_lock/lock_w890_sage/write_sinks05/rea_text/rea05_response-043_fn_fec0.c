
void WS05_fec0(void)

{
  longlong lVar1;
  longlong *plVar2;
  uint uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  
  uVar7 = 0;
  if (0 < DAT_0001dad0) {
    plVar2 = &DAT_0001c38c;
    uVar5 = uVar7;
    do {
      uVar4 = uVar7;
      uVar6 = uVar7;
      if (*(short *)((longlong)plVar2 + -2) != 0) {
        do {
          lVar1 = *plVar2;
          if (*(longlong *)(lVar1 + 8 + uVar6) != 0) {
            FUN_00006148();
            lVar1 = *plVar2;
          }
          if (*(longlong *)(uVar6 + lVar1) != 0) {
            FUN_00006148();
            lVar1 = *plVar2;
          }
          if (*(longlong *)(uVar6 + 0x10 + lVar1) != 0) {
            FUN_00006148();
            lVar1 = *plVar2;
          }
          if (*(longlong *)(uVar6 + 0x18 + lVar1) != 0) {
            FUN_00006148();
          }
          uVar3 = (int)uVar4 + 1;
          uVar4 = (ulonglong)uVar3;
          uVar6 = uVar6 + 0x20;
        } while ((int)uVar3 < (int)(uint)*(ushort *)((longlong)plVar2 + -2));
      }
      if (*plVar2 != 0) {
        FUN_00006148();
        *plVar2 = 0;
      }
      if (plVar2[-3] != 0) {
        FUN_00006148();
        plVar2[-3] = 0;
      }
      if (*(longlong *)((longlong)plVar2 + -0xc) != 0) {
        FUN_00006148();
        *(undefined8 *)((longlong)plVar2 + -0xc) = 0;
      }
      DAT_0001c348 = plVar2[1];
      FUN_00015918();
      plVar2[1] = 0;
      uVar3 = (int)uVar5 + 1;
      uVar5 = (ulonglong)uVar3;
      plVar2 = (longlong *)((longlong)plVar2 + 0x3c);
    } while ((int)uVar3 < DAT_0001dad0);
  }
  FUN_00008954((undefined1 *)&DAT_0001c360,0x1774,0);
  DAT_0001bbf8 = 0;
  return;
}

