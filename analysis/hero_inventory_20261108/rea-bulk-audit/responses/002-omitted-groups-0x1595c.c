
ulonglong FUN_0001595c(longlong param_1,longlong param_2,longlong param_3,ulonglong param_4)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  
  puVar1 = FUN_00016b80();
  if (puVar1 != (undefined1 *)0x0) {
    *(undefined4 *)(puVar1 + 0x18) = 5;
    FUN_00018744(param_2,s_NetworkInterfaces_0001ada8,(longlong)puVar1);
    puVar2 = FUN_00016b80();
    if (puVar2 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar2 + 0x18) = 5;
      FUN_00018744(param_2,s_EthernetInterfaces_0001adc0,(longlong)puVar2);
      puVar3 = FUN_00016b80();
      if (puVar3 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar3 + 0x18) = 5;
        FUN_00018744(param_3,s_NetworkAdapters_0001add8,(longlong)puVar3);
        puVar4 = (undefined8 *)FUN_00016b80();
        if (puVar4 != (undefined8 *)0x0) {
          *(undefined4 *)(puVar4 + 3) = 5;
          FUN_00015880(param_1,(longlong)puVar4);
          uVar5 = FUN_0001554c(param_1,(longlong)puVar1,(longlong)puVar2,(longlong)puVar3,
                               (longlong)puVar4,param_4);
          FUN_00016bcc(puVar4);
          return uVar5;
        }
      }
    }
  }
  return 0x8000000000000009;
}

