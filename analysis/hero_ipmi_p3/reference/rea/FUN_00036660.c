
void FUN_00036660(undefined8 param_1)

{
  if (DAT_00193630 == 0) {
    DAT_00193628 = FUN_000014c8(8);
  }
  else {
    DAT_00193628 = FUN_00001450(DAT_00193628,DAT_00193630 * 8,DAT_00193630 * 8 + 8);
  }
  *(undefined8 *)(DAT_00193628 + DAT_00193630 * 8) = param_1;
  DAT_00193630 = DAT_00193630 + 1;
  return;
}

