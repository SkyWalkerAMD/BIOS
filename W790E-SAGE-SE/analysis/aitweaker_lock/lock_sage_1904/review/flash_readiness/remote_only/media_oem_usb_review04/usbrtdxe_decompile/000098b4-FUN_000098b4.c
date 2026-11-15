
ulonglong FUN_000098b4(byte *param_1)

{
  byte bVar1;
  byte *pbVar2;
  ulonglong uVar3;
  
  pbVar2 = (byte *)FUN_0000340c(-0x80,0,*param_1,(char *)0x0);
  if (pbVar2 == (byte *)0x0) {
    uVar3 = 0xff;
  }
  else {
    bVar1 = pbVar2[0xa0];
    uVar3 = FUN_0000af54(pbVar2);
    if (((pbVar2[0xa0] ^ bVar1) & 1) != 0) {
      pbVar2[0xa0] = pbVar2[0xa0] | 2;
    }
    param_1[1] = pbVar2[0xa0];
    if ((pbVar2[0xa0] & 2) != 0) {
      pbVar2[0xa0] = pbVar2[0xa0] & 0xfd;
    }
    uVar3 = uVar3 & 0xffffffffffffff00;
  }
  return uVar3;
}

