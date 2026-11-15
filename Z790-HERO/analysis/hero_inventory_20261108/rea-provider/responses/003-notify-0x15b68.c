
undefined8 FUN_00015b68(longlong param_1,ulonglong param_2,uint *param_3,uint *param_4,char param_5)

{
  byte *pbVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  uint uVar4;
  ulonglong uVar5;
  uint local_res8 [2];
  
  if (((param_1 == 0) || (param_2 == 0)) || (param_3 == (uint *)0x0)) {
    uVar2 = 0x8000000000000002;
  }
  else {
    uVar3 = 0xffffffff;
    uVar4 = 0xffffffff;
    uVar5 = 0;
    if (param_2 != 0) {
      do {
        pbVar1 = (byte *)(uVar5 + param_1);
        uVar5 = uVar5 + 1;
        uVar4 = *(uint *)(&DAT_00018590 + ((ulonglong)*pbVar1 ^ uVar3 & 0xff) * 4) ^
                (uint)(uVar3 >> 8);
        uVar3 = (ulonglong)uVar4;
      } while (uVar5 < param_2);
    }
    *param_3 = ~uVar4;
    uVar3 = 0;
    local_res8[0] = ~uVar4;
    do {
      pbVar1 = (byte *)((longlong)local_res8 + uVar3);
      uVar3 = uVar3 + 1;
      uVar4 = *(uint *)(&DAT_00018590 + (ulonglong)(byte)(*pbVar1 ^ (byte)*param_4) * 4) ^
              *param_4 >> 8;
      *param_4 = uVar4;
    } while (uVar3 < 4);
    if (param_5 != '\0') {
      *param_4 = ~uVar4;
    }
    uVar2 = 0;
  }
  return uVar2;
}

