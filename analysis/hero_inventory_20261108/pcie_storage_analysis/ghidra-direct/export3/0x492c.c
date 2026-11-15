
ulonglong FUN_0000492c(undefined8 *param_1,byte *param_2,byte *param_3,longlong param_4)

{
  byte bVar1;
  char cVar2;
  byte *pbVar3;
  short *psVar4;
  undefined8 *puVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  ulonglong uVar8;
  byte *pbVar9;
  ulonglong uVar10;
  byte *pbVar11;
  
  pbVar11 = (byte *)0x0;
  bVar1 = *param_3;
  pbVar3 = pbVar11;
  while (bVar1 != 0) {
    pbVar3 = pbVar3 + 1;
    bVar1 = pbVar3[(longlong)param_3];
  }
  cVar2 = **(char **)(param_2 + 0x608);
  pbVar9 = pbVar11;
  while (cVar2 != '\0') {
    pbVar9 = pbVar9 + 1;
    cVar2 = (*(char **)(param_2 + 0x608))[(longlong)pbVar9];
  }
  uVar10 = (longlong)(pbVar3 + (longlong)pbVar9) * 2 + 0x18;
  psVar4 = (short *)FUN_00015ad4(uVar10);
  if (psVar4 == (short *)0x0) {
    return 0x8000000000000009;
  }
  FUN_00015bfc((char *)psVar4,uVar10,(byte *)u__a_Drives__a_0001ac48,(ulonglong)param_3);
  puVar5 = (undefined8 *)FUN_00016b80();
  pbVar3 = pbVar11;
  if (puVar5 != (undefined8 *)0x0) {
    *(undefined4 *)(puVar5 + 3) = 6;
    FUN_00008ab4((longlong)puVar5,param_2);
    puVar6 = FUN_00016b80();
    pbVar3 = (byte *)0x0;
    if (puVar6 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar6 + 0x18) = 6;
      FUN_00018744((longlong)puVar5,s_Links_0001ac64,(longlong)puVar6);
      puVar7 = FUN_00016b80();
      if (puVar7 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar7 + 0x18) = 5;
        FUN_00018744((longlong)puVar6,s_Volumes_0001ac38,(longlong)puVar7);
        uVar8 = FUN_00004858((longlong)param_2,(longlong)puVar7,param_4);
        uVar10 = 0;
        pbVar3 = pbVar11;
        if ((longlong)uVar8 < 0) goto LAB_00004aa6;
        pbVar3 = FUN_0001784c((longlong)puVar5,0,1,(longlong *)0x0);
        if (pbVar3 != (byte *)0x0) {
          bVar1 = *pbVar3;
          while (bVar1 != 0) {
            uVar10 = uVar10 + 1;
            bVar1 = pbVar3[uVar10];
          }
          uVar8 = FUN_00019384(param_1,psVar4,(char *)pbVar3,uVar10,(undefined8 *)0x0);
          goto LAB_00004aa6;
        }
      }
    }
  }
  uVar8 = 0x8000000000000009;
LAB_00004aa6:
  (**(code **)(DAT_0001e070 + 0x48))(psVar4);
  if (puVar5 != (undefined8 *)0x0) {
    FUN_00016bcc(puVar5);
  }
  if (pbVar3 != (byte *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pbVar3);
  }
  return uVar8;
}

