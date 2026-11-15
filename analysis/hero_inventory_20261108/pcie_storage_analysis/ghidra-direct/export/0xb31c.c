
longlong FUN_0000b31c(longlong param_1,longlong param_2)

{
  longlong lVar1;
  short *psVar2;
  longlong *plVar3;
  undefined1 *puVar4;
  longlong *plVar5;
  longlong lVar6;
  ulonglong uVar7;
  
  lVar6 = 0;
  uVar7 = 0;
  if (((param_1 == 0) || (param_2 == 0)) || (*(int *)(param_2 + 0x18) != 5)) {
    lVar6 = -0x7ffffffffffffffe;
  }
  else if (*(longlong *)(param_1 + 0x330) != 0) {
    do {
      lVar1 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar7 * 8);
      if (*(char *)(lVar1 + 0x18) == '\x04') {
        psVar2 = *(short **)(lVar1 + 0x20);
        puVar4 = FUN_00016b80();
        if (puVar4 == (undefined1 *)0x0) {
          return -0x7ffffffffffffff7;
        }
        *(undefined4 *)(puVar4 + 0x18) = 6;
        plVar3 = *(longlong **)(param_2 + 0x10);
        if (*(longlong **)(param_2 + 0x10) == (longlong *)0x0) {
          *(undefined1 **)(param_2 + 0x10) = puVar4;
        }
        else {
          do {
            plVar5 = plVar3;
            plVar3 = (longlong *)*plVar5;
          } while ((longlong *)*plVar5 != (longlong *)0x0);
          *plVar5 = (longlong)puVar4;
          *(longlong **)(puVar4 + 8) = plVar5;
        }
        lVar6 = FUN_000096a8(lVar1 + 0x28,(longlong)puVar4,psVar2);
        if (lVar6 < 0) {
          return lVar6;
        }
        lVar6 = FUN_000095ac(lVar1 + 0x28,(longlong)puVar4,param_1);
        if (lVar6 < 0) {
          return lVar6;
        }
      }
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ulonglong *)(param_1 + 0x330));
  }
  return lVar6;
}

