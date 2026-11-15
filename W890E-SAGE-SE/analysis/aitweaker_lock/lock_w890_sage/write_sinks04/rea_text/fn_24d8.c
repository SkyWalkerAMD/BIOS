
void FUN_000024d8(longlong param_1,ulonglong param_2,byte *param_3)

{
  char cVar1;
  byte bVar2;
  char cVar3;
  ulonglong uVar4;
  
  uVar4 = 0;
  if (param_2 != 0) {
    do {
      if (uVar4 == param_2 - 1) {
        cVar1 = *(char *)(param_1 + uVar4 * 2);
        cVar3 = '\0';
      }
      else {
        cVar3 = *(char *)(param_1 + uVar4 * 2);
        if ((byte)(cVar3 - 0x30U) < 10) {
          cVar3 = cVar3 + -0x30;
        }
        else if ((byte)(cVar3 + 0xbfU) < 6) {
          cVar3 = cVar3 + -0x37;
        }
        else {
          cVar3 = cVar3 + -0x57;
        }
        cVar1 = *(char *)(param_1 + 2 + uVar4 * 2);
      }
      if ((byte)(cVar1 - 0x30U) < 10) {
        bVar2 = cVar1 - 0x30;
      }
      else if ((byte)(cVar1 + 0xbfU) < 6) {
        bVar2 = cVar1 - 0x37;
      }
      else {
        bVar2 = cVar1 + 0xa9;
      }
      uVar4 = uVar4 + 2;
      *param_3 = cVar3 << 4 | bVar2;
      param_3 = param_3 + 1;
    } while (uVar4 < param_2);
  }
  return;
}

