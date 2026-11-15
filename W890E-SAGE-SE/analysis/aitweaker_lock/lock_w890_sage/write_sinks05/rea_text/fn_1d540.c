
void WS05_1d540(longlong *param_1,uint param_2)

{
  undefined8 *puVar1;
  ulonglong local_res18 [2];
  
  puVar1 = FUN_0001c6d0((ulonglong)param_2,local_res18);
  if (puVar1 != (undefined8 *)0x0) {
    if ((param_1 != (longlong *)0x0) && (*param_1 != 0)) {
      (**(code **)(DAT_000afbc8 + 0x48))();
    }
    param_1[1] = local_res18[0];
    *param_1 = (longlong)puVar1;
  }
  return;
}

