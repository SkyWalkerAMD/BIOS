
ulonglong FUN_0000586c(byte *param_1,undefined8 *param_2,short *param_3,undefined8 param_4,
                      longlong *param_5,longlong *param_6,undefined8 *param_7)

{
  byte bVar1;
  byte *pbVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  short *local_res8;
  
  pbVar2 = (byte *)0x0;
  pbVar5 = (byte *)0x0;
  puVar6 = (undefined8 *)0x0;
  local_res8 = (short *)0x0;
  if ((((param_1 == (byte *)0x0) || (param_2 == (undefined8 *)0x0)) || (param_5 == (longlong *)0x0))
     || (param_6 == (longlong *)0x0)) {
    uVar4 = 0x8000000000000002;
    goto LAB_00005a39;
  }
  puVar6 = (undefined8 *)FUN_00016b80();
  if (puVar6 != (undefined8 *)0x0) {
    *(undefined4 *)(puVar6 + 3) = 6;
    uVar4 = FUN_000102c0(param_1,param_5,param_6,(longlong)puVar6);
    pbVar5 = pbVar2;
    if ((longlong)uVar4 < 0) goto LAB_00005a39;
    pbVar2 = FUN_0001784c((longlong)puVar6,0,1,(longlong *)0x0);
    if (pbVar2 != (byte *)0x0) {
      uVar4 = 0;
      bVar1 = *pbVar2;
      while (bVar1 != 0) {
        uVar4 = uVar4 + 1;
        bVar1 = pbVar2[uVar4];
      }
      uVar4 = FUN_00019384(param_2,param_3,(char *)pbVar2,uVar4,param_7);
      pbVar5 = pbVar2;
      if ((-1 < (longlong)uVar4) && ((byte *)*param_7 != (byte *)0x0)) {
        if ((param_1[0x268] != 0) &&
           ((uVar3 = FUN_00000854(param_2,(byte *)*param_7,s_Assembly_0001a110,&local_res8),
            -1 < (longlong)uVar3 && (local_res8 != (short *)0x0)))) {
          uVar4 = FUN_00003f3c(param_1 + 0x268,param_2,local_res8);
          (**(code **)(DAT_0001e070 + 0x48))(local_res8);
          local_res8 = (short *)0x0;
          if ((longlong)uVar4 < 0) goto LAB_00005a39;
        }
        if ((((param_1[3] != 0) && (*(longlong *)(param_1 + 0x120) != 0)) &&
            ((param_1[0x19c] & 3) == 3)) &&
           ((uVar3 = FUN_00000854(param_2,(byte *)*param_7,s_Metrics_0001ac90,&local_res8),
            -1 < (longlong)uVar3 && (local_res8 != (short *)0x0)))) {
          uVar4 = FUN_0000575c((longlong)param_1,param_2,local_res8);
          (**(code **)(DAT_0001e070 + 0x48))(local_res8);
        }
      }
      goto LAB_00005a39;
    }
  }
  uVar4 = 0x8000000000000009;
  pbVar5 = pbVar2;
LAB_00005a39:
  if (puVar6 != (undefined8 *)0x0) {
    FUN_00016bcc(puVar6);
  }
  if (pbVar5 != (byte *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pbVar5);
  }
  return uVar4;
}

