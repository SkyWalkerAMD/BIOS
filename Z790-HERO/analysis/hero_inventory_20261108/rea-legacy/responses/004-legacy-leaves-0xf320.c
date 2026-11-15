
ulonglong FUN_0000f320(byte *param_1,undefined8 *param_2,short *param_3,undefined8 param_4,
                      longlong *param_5)

{
  byte bVar1;
  short *psVar2;
  undefined1 *puVar3;
  byte *pbVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  byte *pbVar7;
  undefined8 *puVar8;
  byte *pbVar9;
  short *local_res8;
  byte *local_38 [2];
  
  puVar8 = (undefined8 *)0x0;
  pbVar9 = (byte *)0x0;
  local_res8 = (short *)0x0;
  pbVar4 = (byte *)0x0;
  pbVar7 = (byte *)0x0;
  local_38[0] = (byte *)0x0;
  if ((param_1 == (byte *)0x0) || (param_5 == (longlong *)0x0)) {
    uVar6 = 0x8000000000000002;
    goto LAB_0000f506;
  }
  puVar8 = (undefined8 *)FUN_00016b80();
  if (puVar8 != (undefined8 *)0x0) {
    *(undefined4 *)(puVar8 + 3) = 6;
    uVar6 = FUN_0000ce60((longlong)puVar8,param_1,param_5);
    pbVar7 = pbVar4;
    if ((longlong)uVar6 < 0) goto LAB_0000f518;
    puVar3 = FUN_00016b80();
    if (puVar3 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar3 + 0x18) = 5;
      FUN_00018744((longlong)puVar8,s_SubProcessors_0001c0c8,(longlong)puVar3);
      uVar6 = FUN_0000f174((longlong)param_1,(longlong)puVar3);
      if ((longlong)uVar6 < 0) goto LAB_0000f518;
      pbVar4 = FUN_0001784c((longlong)puVar8,0,1,(longlong *)0x0);
      if (pbVar4 != (byte *)0x0) {
        uVar6 = 0;
        bVar1 = *pbVar4;
        while (bVar1 != 0) {
          uVar6 = uVar6 + 1;
          bVar1 = pbVar4[uVar6];
        }
        uVar6 = FUN_00019384(param_2,param_3,(char *)pbVar4,uVar6,local_38);
        pbVar9 = local_38[0];
        pbVar7 = pbVar4;
        if (-1 < (longlong)uVar6) {
          if (local_38[0] == (byte *)0x0) goto LAB_0000f518;
          if ((((*(int *)(param_1 + 0xc4) != 0) && ((param_1[0x37c] & 3) == 3)) &&
              (uVar5 = FUN_00000854(param_2,local_38[0],s_Metrics_0001ac90,&local_res8),
              psVar2 = local_res8, -1 < (longlong)uVar5)) && (local_res8 != (short *)0x0)) {
            uVar6 = FUN_0000f230(param_1,param_2,local_res8);
            (**(code **)(DAT_0001e070 + 0x48))(psVar2);
            local_res8 = (short *)0x0;
            if ((longlong)uVar6 < 0) goto LAB_0000f506;
          }
          if (((param_1[0xe0] != 0) &&
              (uVar5 = FUN_00000854(param_2,pbVar9,s_Assembly_0001a110,&local_res8),
              psVar2 = local_res8, -1 < (longlong)uVar5)) && (local_res8 != (short *)0x0)) {
            uVar6 = FUN_00003f3c(param_1 + 0xe0,param_2,local_res8);
            (**(code **)(DAT_0001e070 + 0x48))(psVar2);
          }
        }
LAB_0000f506:
        if (pbVar9 != (byte *)0x0) {
          (**(code **)(DAT_0001e070 + 0x48))(pbVar9);
        }
        goto LAB_0000f518;
      }
    }
  }
  uVar6 = 0x8000000000000009;
  pbVar7 = pbVar4;
LAB_0000f518:
  if (puVar8 != (undefined8 *)0x0) {
    FUN_00016bcc(puVar8);
  }
  if (pbVar7 != (byte *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pbVar7);
  }
  return uVar6;
}

