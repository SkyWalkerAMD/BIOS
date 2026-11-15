
ulonglong FUN_0000d29c(byte *param_1,longlong *param_2,longlong param_3)

{
  longlong *plVar1;
  undefined1 *puVar2;
  longlong *plVar3;
  ulonglong uVar4;
  undefined1 *puVar5;
  
  if (param_3 == 0) {
    return 0x8000000000000002;
  }
  puVar2 = FUN_00016b80();
  if (puVar2 != (undefined1 *)0x0) {
    *(undefined4 *)(puVar2 + 0x18) = 6;
    plVar1 = *(longlong **)(param_3 + 0x10);
    if (*(longlong **)(param_3 + 0x10) == (longlong *)0x0) {
      *(undefined1 **)(param_3 + 0x10) = puVar2;
    }
    else {
      do {
        plVar3 = plVar1;
        plVar1 = (longlong *)*plVar3;
      } while ((longlong *)*plVar3 != (longlong *)0x0);
      *plVar3 = (longlong)puVar2;
      *(longlong **)(puVar2 + 8) = plVar3;
    }
    uVar4 = FUN_0000ce60((longlong)puVar2,param_1,param_2);
    if ((longlong)uVar4 < 0) {
      return uVar4;
    }
    uVar4 = FUN_00003d30(param_1 + 0xe0,(longlong)puVar2);
    if ((longlong)uVar4 < 0) {
      return uVar4;
    }
    if ((param_1[0x37c] & 1) != 0) {
      puVar5 = FUN_00016b80();
      if (puVar5 == (undefined1 *)0x0) {
        return 0x8000000000000009;
      }
      *(undefined4 *)(puVar5 + 0x18) = 6;
      FUN_00018744((longlong)puVar2,s_ProcessorMetrics_0001c0b0,(longlong)puVar5);
      uVar4 = FUN_0000cb58(param_1,(longlong)puVar5);
      if ((longlong)uVar4 < 0) {
        return uVar4;
      }
    }
    if (param_1[1] == 0) {
      return uVar4;
    }
    puVar5 = FUN_00016b80();
    if (puVar5 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar5 + 0x18) = 5;
      FUN_00018744((longlong)puVar2,s_SubProcessors_0001c0c8,(longlong)puVar5);
      uVar4 = FUN_0000f174((longlong)param_1,(longlong)puVar5);
      return uVar4;
    }
  }
  return 0x8000000000000009;
}

