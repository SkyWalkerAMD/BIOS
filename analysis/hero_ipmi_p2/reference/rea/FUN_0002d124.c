ushort FUN_0002d124(ulonglong param_1)
{
  ulonglong uVar1;
  ushort *puVar2;
  bool bVar3;
  puVar2 = DAT_00183768 + 1;
  uVar1 = 0;
  do {
    if (*puVar2 == param_1) {
      return DAT_00183768[(uVar1 + 1) * 3];
    }
    puVar2 = puVar2 + 3;
    bVar3 = uVar1 < *DAT_00183768;
    uVar1 = uVar1 + 1;
  } while (bVar3);
  return 0;
}