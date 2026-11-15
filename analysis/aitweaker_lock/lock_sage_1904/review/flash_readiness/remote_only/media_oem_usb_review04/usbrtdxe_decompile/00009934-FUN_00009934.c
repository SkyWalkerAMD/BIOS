
undefined8 FUN_00009934(byte *param_1)

{
  int iVar1;
  byte *pbVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  byte *pbVar5;
  undefined1 *puVar6;
  undefined8 *puVar7;
  uint uVar8;
  byte bVar9;
  undefined8 *local_38;
  byte local_30;
  byte bStack_2f;
  uint6 uStack_2e;
  undefined2 local_28;
  uint uStack_26;
  undefined2 uStack_22;
  undefined4 local_20;
  
  pbVar2 = (byte *)FUN_0000340c(-0x80,0,*param_1,(char *)0x0);
  pbVar5 = pbVar2;
  if ((pbVar2 != (byte *)0x0) && ((*pbVar2 & 2) != 0)) {
    uVar8 = *(ushort *)(param_1 + 9) + 0x1f >> 5;
    FUN_0000af54(pbVar2);
    puVar3 = (undefined8 *)FUN_00002f1c((ushort)((ulonglong)(uVar8 & 0xff) + 0x1f >> 5));
    pbVar5 = (byte *)0x0;
    if (puVar3 != (undefined8 *)0x0) {
      puVar6 = (undefined1 *)(ulonglong)*(uint *)(param_1 + 5);
      bVar9 = 0;
      puVar7 = puVar3;
      if (*(short *)(param_1 + 9) != 0) {
        do {
          bVar9 = bVar9 + 1;
          *(undefined1 *)puVar7 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar7 = (undefined8 *)((longlong)puVar7 + 1);
        } while ((ushort)bVar9 < *(ushort *)(param_1 + 9));
      }
      local_30 = param_1[9];
      bStack_2f = param_1[0x11];
      uStack_22 = 0;
      uStack_2e = (uint6)*(uint *)(param_1 + 0xb);
      local_28 = 0;
      uStack_26 = (uint)*(ushort *)(param_1 + 0xf);
      local_20 = 0;
      local_38 = puVar3;
      uVar4 = FUN_00009640((longlong)pbVar2,&local_38);
      *(short *)(param_1 + 0xf) = (short)uVar4;
      iVar1 = FUN_0000ae3c((longlong)pbVar2);
      *(int *)(param_1 + 1) = iVar1;
      uVar4 = FUN_000030f0(puVar3,(ushort)(((ushort)uVar8 & 0xff) + 0x1f) >> 5);
      return uVar4 & 0xffffffffffffff00;
    }
  }
  return CONCAT71((int7)((ulonglong)pbVar5 >> 8),0xff);
}

