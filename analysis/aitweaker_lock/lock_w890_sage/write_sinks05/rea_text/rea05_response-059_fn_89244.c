
undefined8 WS05_89244(ushort *param_1,char *param_2,longlong *param_3,undefined8 *param_4)

{
  longlong lVar1;
  ulonglong uVar2;
  longlong lVar3;
  char *pcVar4;
  uint *puVar5;
  
  if ((DAT_000baaf8 != (uint *)0x0) && (uVar2 = 0, *DAT_000baaf8 != 0)) {
    lVar3 = 0;
    puVar5 = DAT_000baaf8;
    do {
      pcVar4 = (char *)((ulonglong)puVar5[uVar2 + 1] + (longlong)puVar5);
      lVar1 = FUN_00059000(param_1,(ushort *)(pcVar4 + 0x10));
      if (((lVar1 == 0) &&
          (((param_2 == pcVar4 ||
            (lVar1 = FUN_000015e0(param_2,pcVar4,0x10), puVar5 = DAT_000baaf8, lVar1 == 0)) &&
           (*(longlong *)(lVar3 + DAT_000afcd8) != 0)))) &&
         (*(longlong *)(lVar3 + 8 + DAT_000afcd8) != 0)) {
        *param_3 = *(longlong *)(lVar3 + DAT_000afcd8);
        *param_4 = *(undefined8 *)(DAT_000afcd8 + 8 + uVar2 * 0x10);
        return 0;
      }
      uVar2 = uVar2 + 1;
      lVar3 = lVar3 + 0x10;
    } while (uVar2 < *puVar5);
  }
  return 0x800000000000000e;
}

