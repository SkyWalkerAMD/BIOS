
ulonglong FUN_0000a4b8(byte *param_1,char *param_2)

{
  byte bVar1;
  int iVar2;
  undefined8 uVar3;
  uint *puVar4;
  byte bVar5;
  short sVar6;
  short sVar7;
  short local_res8 [4];
  
  sVar7 = 0;
  bVar5 = 0;
  if (*param_2 == '\0') {
    if (param_1[0x58] == 4) {
      param_1[0x75] = 4;
    }
    else {
      bVar1 = (byte)(param_2[1] | 0x40U) >> 6;
LAB_0000a513:
      param_1[0x75] = bVar1;
    }
  }
  else if (*param_2 == '\x05') {
    param_1[0x75] = 2;
  }
  else {
    if (*param_2 != '\a') {
      bVar1 = (*param_2 != '\x0e') - 1U & 3;
      goto LAB_0000a513;
    }
    param_1[0x75] = 5;
  }
  if (((*param_1 & 0x10) == 0) || (*(short *)(param_1 + 0x5a) != 0)) {
    sVar7 = *(short *)(&DAT_0001aad0 + (ulonglong)*(ushort *)(param_1 + 0x5a) * 2);
  }
  if (((*(uint *)((longlong)DAT_0001b2c0 + 0x6c9) & 0x2000) == 0) || (param_2[1] < '\0')) {
    param_1[0xa0] = param_1[0xa0] | 8;
  }
  param_1[0xa0] = param_1[0xa0] | 1;
  if (*param_2 == '\x05') {
    param_1[0x5e] = 0;
    param_1[0x5f] = 8;
    puVar4 = (uint *)0x800;
    sVar6 = 0x302;
    goto LAB_0000a6c3;
  }
  if ((*(uint *)((longlong)DAT_0001b2c0 + 0x6c9) & 0x100000) != 0) {
    FUN_0000ac5c((longlong)param_1);
  }
  if (param_1[0x58] == 4) {
    sVar6 = 0x103;
    local_res8[0] = 0x103;
  }
  else {
    sVar6 = 0x201;
    local_res8[0] = 0x201;
  }
  (**(code **)(DAT_0001abe0 + 0xf8))
            ((ulonglong)*(ushort *)(*(longlong *)(DAT_0001ab98 + 0x3a2) + 0x18) * 1000);
  if (param_1[0x58] != 4) {
    do {
      if (((*param_1 & 3) == 0) || (uVar3 = FUN_00009bd0(param_1), (char)uVar3 == '\0')) break;
      bVar1 = *(byte *)((longlong)DAT_0001b2c0 + 0x6c2);
      iVar2 = FUN_0000ae3c((longlong)param_1);
      if ((short)iVar2 == 0x3a02) break;
      if (((*(byte *)((longlong)DAT_0001b2c0 + 0x6c2) & 2) != 0) && ((bVar1 & 2) != 0)) {
        return CONCAT71((int7)((ulonglong)DAT_0001b2c0 >> 8),0xff);
      }
      bVar5 = bVar5 + 1;
    } while (bVar5 < 0x1e);
  }
  puVar4 = (uint *)FUN_0000af54(param_1);
  if (((short)puVar4 == 0x3a02) && ((param_1[0x7c] & 0x40) == 0)) {
    FUN_00009d58((longlong)param_1);
    if ((uint *)(*(longlong *)(param_1 + 0x60) + -1) < (uint *)0xb40) {
      puVar4 = (uint *)(*(longlong *)(param_1 + 0x60) + -1);
      sVar6 = 0x103;
      goto LAB_0000a6c3;
    }
    puVar4 = DAT_0001b2c0;
    if ((*DAT_0001b2c0 & 0x40000) != 0) goto LAB_0000a6c3;
  }
  else if ((((int)puVar4 != 0) ||
           (puVar4 = (uint *)FUN_0000a1b4(param_1,*(ulonglong *)(param_1 + 0x60),local_res8),
           sVar6 = local_res8[0], (char)puVar4 != -1)) ||
          (((puVar4 = (uint *)(*(ulonglong *)(param_1 + 0x60) >> 0xb),
            *(uint **)((longlong)DAT_0001b2c0 + 0x71b) <= puVar4 && ((*DAT_0001b2c0 & 0x1000) == 0))
           || (param_1[0x58] == 4)))) goto LAB_0000a6c3;
  sVar6 = 0x403;
LAB_0000a6c3:
  if (sVar7 != 0) {
    sVar6 = sVar7;
  }
  param_1[0x4c] = (byte)sVar6;
  param_1[0x74] = (byte)((ushort)sVar6 >> 8);
  return (ulonglong)puVar4 & 0xffffffffffffff00;
}

