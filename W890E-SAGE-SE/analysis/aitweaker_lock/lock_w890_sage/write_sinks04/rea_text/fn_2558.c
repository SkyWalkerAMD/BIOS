
void FUN_00002558(longlong param_1,ulonglong *param_2,longlong param_3)

{
  char cVar1;
  short sVar2;
  byte bVar3;
  ushort uVar4;
  ulonglong uVar5;
  short *psVar6;
  
  psVar6 = (short *)(param_1 + 4);
  uVar5 = 0;
  while( true ) {
    sVar2 = psVar6[-2];
    if (((ushort)(sVar2 - 0x47U) < 0x1a) ||
       ((ushort)(sVar2 - 0x3aU) < 7 || 0x36 < (ushort)(sVar2 - 0x30U))) break;
    sVar2 = psVar6[-1];
    if (((ushort)(sVar2 - 0x47U) < 0x1a) ||
       ((ushort)(sVar2 - 0x3aU) < 7 || 0x36 < (ushort)(sVar2 - 0x30U))) break;
    sVar2 = *psVar6;
    if (((ushort)(sVar2 - 0x47U) < 0x1a) ||
       ((ushort)(sVar2 - 0x3aU) < 7 || 0x36 < (ushort)(sVar2 - 0x30U))) break;
    sVar2 = psVar6[1];
    if (((ushort)(sVar2 - 0x47U) < 0x1a) ||
       (((ushort)(sVar2 - 0x3aU) < 7 || 0x36 < (ushort)(sVar2 - 0x30U) || (*param_2 - 1 <= uVar5))))
    break;
    cVar1 = (char)psVar6[-2];
    if ((byte)(cVar1 - 0x30U) < 10) {
      bVar3 = cVar1 - 0x30;
    }
    else if ((byte)(cVar1 + 0xbfU) < 6) {
      bVar3 = cVar1 - 0x37;
    }
    else {
      bVar3 = cVar1 + 0xa9;
    }
    uVar4 = (ushort)(bVar3 & 0xf) << 4;
    *(ushort *)(param_3 + uVar5 * 2) = uVar4;
    cVar1 = (char)psVar6[-1];
    if ((byte)(cVar1 - 0x30U) < 10) {
      bVar3 = cVar1 - 0x30;
    }
    else if ((byte)(cVar1 + 0xbfU) < 6) {
      bVar3 = cVar1 - 0x37;
    }
    else {
      bVar3 = cVar1 + 0xa9;
    }
    uVar4 = (bVar3 | uVar4) << 4;
    *(ushort *)(param_3 + uVar5 * 2) = uVar4;
    cVar1 = (char)*psVar6;
    if ((byte)(cVar1 - 0x30U) < 10) {
      bVar3 = cVar1 - 0x30;
    }
    else if ((byte)(cVar1 + 0xbfU) < 6) {
      bVar3 = cVar1 - 0x37;
    }
    else {
      bVar3 = cVar1 + 0xa9;
    }
    uVar4 = (bVar3 | uVar4) << 4;
    *(ushort *)(param_3 + uVar5 * 2) = uVar4;
    cVar1 = (char)psVar6[1];
    if ((byte)(cVar1 - 0x30U) < 10) {
      bVar3 = cVar1 - 0x30;
    }
    else if ((byte)(cVar1 + 0xbfU) < 6) {
      bVar3 = cVar1 - 0x37;
    }
    else {
      bVar3 = cVar1 + 0xa9;
    }
    psVar6 = psVar6 + 4;
    *(ushort *)(param_3 + uVar5 * 2) = bVar3 | uVar4;
    uVar5 = uVar5 + 1;
  }
  *param_2 = uVar5;
  *(undefined2 *)(param_3 + uVar5 * 2) = 0;
  return;
}

