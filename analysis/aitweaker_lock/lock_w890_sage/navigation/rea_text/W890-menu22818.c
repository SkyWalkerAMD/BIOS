
void FUN_00022818(undefined8 param_1,undefined8 param_2,int *param_3)

{
  if ((param_3 != (int *)0x0) && (*param_3 == 8)) {
    *(uint *)(DAT_000afdd0 + 0x28) = (uint)*(ushort *)(param_3 + 2);
    *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
    *(undefined4 *)(DAT_000afdd0 + 0x5c) = 1;
    if (DAT_000afde8 != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
      DAT_000afde8 = 0;
    }
    DAT_000afe00 = 0;
    DAT_000afddc = 0;
  }
  return;
}

