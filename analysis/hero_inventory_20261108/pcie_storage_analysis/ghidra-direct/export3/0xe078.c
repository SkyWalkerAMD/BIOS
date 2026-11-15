
ulonglong FUN_0000e078(longlong param_1,longlong param_2,undefined8 *param_3,char *param_4,
                      longlong param_5,longlong param_6)

{
  longlong *plVar1;
  undefined1 *puVar2;
  longlong *plVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  
  if ((((param_4 != (char *)0x0) && (param_3 != (undefined8 *)0x0)) && (param_2 != 0)) &&
     (param_1 != 0)) {
    if (*(short *)(param_2 + 0x1d0) == 0) {
      return 0;
    }
    if ((*(byte *)(param_2 + 0x1d0) & 0xc) == 0xc) {
      puVar2 = FUN_00016b80();
      if (puVar2 == (undefined1 *)0x0) {
        return 0x8000000000000009;
      }
      *(undefined4 *)(puVar2 + 0x18) = 6;
      plVar1 = *(longlong **)(param_1 + 0x10);
      if (*(longlong **)(param_1 + 0x10) == (longlong *)0x0) {
        *(undefined1 **)(param_1 + 0x10) = puVar2;
      }
      else {
        do {
          plVar3 = plVar1;
          plVar1 = (longlong *)*plVar3;
        } while ((longlong *)*plVar3 != (longlong *)0x0);
        *plVar3 = (longlong)puVar2;
        *(longlong **)(puVar2 + 8) = plVar3;
      }
      puVar4 = FUN_0001880c(param_4);
      FUN_00018744((longlong)puVar2,s__odata_id_00019b40,(longlong)puVar4);
      uVar5 = FUN_0000dcac((longlong)puVar2,param_2);
      if ((longlong)uVar5 < 0) {
        return uVar5;
      }
      uVar5 = FUN_0000daec(param_5,(longlong)puVar2,param_3,param_6);
      return uVar5;
    }
  }
  return 0x8000000000000002;
}

