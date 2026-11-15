
undefined8 * FUN_0000e928(longlong param_1,longlong param_2,longlong param_3,ulonglong param_4)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  undefined8 *puVar4;
  
  if ((((param_1 == 0) || (param_2 == 0)) || (param_3 == 0)) || (param_4 == 0)) {
    puVar4 = (undefined8 *)0x8000000000000002;
  }
  else {
    puVar1 = FUN_00016b80();
    if (puVar1 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar1 + 0x18) = 5;
      FUN_00018744(param_3,s_PCIeDevices_0001a120,(longlong)puVar1);
      puVar2 = FUN_00016b80();
      if (puVar2 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar2 + 0x18) = 5;
        FUN_00018744(param_2,s_PCIeDevices_0001a120,(longlong)puVar2);
        puVar3 = FUN_00016b80();
        if (puVar3 != (undefined1 *)0x0) {
          *(undefined4 *)(puVar3 + 0x18) = 5;
          FUN_00018744(param_2,s_PCIeFunctions_0001acb8,(longlong)puVar3);
          puVar4 = FUN_0000e6a8((longlong)puVar1,param_1,(longlong)puVar2,(longlong)puVar3,param_4);
          return puVar4;
        }
      }
    }
    puVar4 = (undefined8 *)0x8000000000000009;
  }
  return puVar4;
}

