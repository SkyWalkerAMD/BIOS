
undefined8 WS05_10950(longlong param_1,longlong *param_2,longlong param_3,ulonglong param_4)

{
  longlong lVar1;
  byte bVar2;
  short sVar3;
  undefined8 uVar4;
  byte bVar5;
  ulonglong uVar6;
  short *psVar7;
  
  lVar1 = *param_2;
  *param_2 = param_4 * 2 + 1;
  if (lVar1 - 1U < param_4 * 2) {
    uVar4 = 0x8000000000000005;
  }
  else {
    uVar6 = 0;
    *(undefined2 *)(param_1 + param_4 * 4) = 0;
    if (param_4 != 0) {
      psVar7 = (short *)(param_1 + -4 + param_4 * 4);
      do {
        bVar2 = *(byte *)(uVar6 + param_3) & 0xf;
        sVar3 = 0x30;
        if (9 < bVar2) {
          sVar3 = 0x37;
        }
        bVar5 = *(byte *)(uVar6 + param_3) >> 4;
        psVar7[1] = sVar3 + (ushort)bVar2;
        sVar3 = 0x30;
        if (9 < bVar5) {
          sVar3 = 0x37;
        }
        uVar6 = uVar6 + 1;
        *psVar7 = sVar3 + (ushort)bVar5;
        psVar7 = psVar7 + -2;
      } while (uVar6 < param_4);
    }
    uVar4 = 0;
  }
  return uVar4;
}

