
undefined8 FUN_00000708(longlong param_1,char *param_2,undefined8 param_3)

{
  longlong *plVar1;
  undefined1 *puVar2;
  longlong lVar3;
  undefined1 *puVar4;
  undefined8 uVar5;
  longlong *plVar6;
  
  puVar2 = FUN_00016b80();
  if (puVar2 == (undefined1 *)0x0) {
    uVar5 = 0x8000000000000009;
  }
  else {
    *(undefined4 *)(puVar2 + 0x18) = 6;
    plVar1 = *(longlong **)(param_1 + 0x10);
    if (*(longlong **)(param_1 + 0x10) == (longlong *)0x0) {
      *(undefined1 **)(param_1 + 0x10) = puVar2;
    }
    else {
      do {
        plVar6 = plVar1;
        plVar1 = (longlong *)*plVar6;
      } while ((longlong *)*plVar6 != (longlong *)0x0);
      *plVar6 = (longlong)puVar2;
      *(longlong **)(puVar2 + 8) = plVar6;
    }
    lVar3 = FUN_000187d8(param_3);
    FUN_00018744((longlong)puVar2,s_DeviceInstance_00019b20,lVar3);
    puVar4 = FUN_0001880c(param_2);
    FUN_00018744((longlong)puVar2,s_LocationLink_00019b30,(longlong)puVar4);
    uVar5 = 0;
  }
  return uVar5;
}

