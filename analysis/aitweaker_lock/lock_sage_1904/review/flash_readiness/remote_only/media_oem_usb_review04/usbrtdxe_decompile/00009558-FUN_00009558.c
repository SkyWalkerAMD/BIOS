
void FUN_00009558(longlong param_1,byte param_2)

{
  byte bVar1;
  longlong lVar2;
  longlong lVar3;
  ushort uVar4;
  
  bVar1 = *(byte *)(param_1 + 0x55) | 0x80;
  if ((param_2 & 0x80) == 0) {
    bVar1 = *(byte *)(param_1 + 0x56);
  }
  FUN_00019e34(*(longlong *)(DAT_0001aba8 + (longlong)(int)(*(byte *)(param_1 + 0xb) - 1) * 8),
               param_1,0x102,(ushort)bVar1,0,0,0);
  uVar4 = (ushort)(byte)((bVar1 & 0xf) - 1);
  if ((param_2 & 0x80) == 0) {
    *(ushort *)(param_1 + 0x4a) = *(ushort *)(param_1 + 0x4a) & ~(1 << (uVar4 & 0xf));
  }
  else {
    *(ushort *)(param_1 + 0x48) = *(ushort *)(param_1 + 0x48) & ~(1 << (uVar4 & 0xf));
  }
  lVar3 = *(longlong *)(param_1 + 0x40);
  if (lVar3 != 0) {
    lVar2 = FUN_0000b9dc(lVar3);
    if (-1 < lVar2) {
      if ((char)param_2 < '\0') {
        *(ushort *)(lVar3 + 0x48) = *(ushort *)(lVar3 + 0x48) & ~(1 << (uVar4 & 0xf));
      }
      else {
        *(ushort *)(lVar3 + 0x4a) = *(ushort *)(lVar3 + 0x4a) & ~(1 << (uVar4 & 0xf));
      }
    }
  }
  return;
}

