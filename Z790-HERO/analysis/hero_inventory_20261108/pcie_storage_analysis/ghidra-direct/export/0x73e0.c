
longlong FUN_000073e0(undefined8 param_1,undefined8 param_2,longlong param_3,longlong param_4,
                     undefined8 param_5)

{
  undefined8 *puVar1;
  undefined1 *puVar2;
  longlong lVar3;
  
  puVar1 = (undefined8 *)FUN_00016b80();
  if (puVar1 != (undefined8 *)0x0) {
    *(undefined4 *)(puVar1 + 3) = 5;
    FUN_00018744(param_3,s_PCIeDevices_0001a120,(longlong)puVar1);
    puVar2 = FUN_00016b80();
    if (puVar2 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar2 + 0x18) = 5;
      FUN_00018744(param_3,s_PCIeFunctions_0001acb8,(longlong)puVar2);
      lVar3 = func_0x0000710c(param_1,param_2,puVar1,puVar2,param_5);
      if (lVar3 < 0) {
        return lVar3;
      }
      puVar1 = FUN_000186f0(puVar1);
      FUN_00018744(param_4,s_PCIeDevices_0001a120,(longlong)puVar1);
      return lVar3;
    }
  }
  return -0x7ffffffffffffff7;
}

