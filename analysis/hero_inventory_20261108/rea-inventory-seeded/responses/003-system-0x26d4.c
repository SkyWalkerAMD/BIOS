
longlong SerializeChassis_from_disassembly(longlong param_1,longlong param_2)

{
  longlong lVar1;
  undefined1 *puVar2;
  
  lVar1 = FUN_00001a64(param_1,param_2);
  if (-1 < lVar1) {
    lVar1 = FUN_00003d30((byte *)(param_1 + 0x1d0),param_2);
    if (-1 < lVar1) {
      if ((*(byte *)(param_1 + 0x2a8) & 3) == 3) {
        puVar2 = FUN_00016b80();
        if (puVar2 == (undefined1 *)0x0) {
          lVar1 = -0x7ffffffffffffff7;
        }
        else {
          *(undefined4 *)(puVar2 + 0x18) = 6;
          FUN_00018744(param_2,s_PCIeSlots_0001a0a8,(longlong)puVar2);
          lVar1 = FUN_00001814(param_1,(byte *)(param_1 + 0x2a8),(longlong)puVar2);
        }
      }
      else {
        lVar1 = -0x7ffffffffffffffe;
      }
    }
  }
  return lVar1;
}

