
ushort * FUN_000051b4(undefined8 *param_1,longlong param_2,longlong param_3,longlong param_4,
                     longlong param_5,longlong param_6,longlong *param_7)

{
  byte bVar1;
  longlong lVar2;
  byte *pbVar3;
  ushort *puVar4;
  undefined8 *puVar5;
  undefined1 *puVar6;
  byte *pbVar7;
  undefined8 *puVar8;
  ushort *puVar9;
  undefined8 *puVar10;
  ulonglong uVar11;
  short *local_res18;
  longlong local_res20;
  byte *local_48;
  undefined8 *local_40;
  
  puVar10 = (undefined8 *)0x0;
  local_res18 = (short *)0x0;
  local_48 = (byte *)0x0;
  puVar5 = (undefined8 *)0x0;
  puVar8 = (undefined8 *)0x0;
  pbVar7 = (byte *)0x0;
  local_res20 = param_4;
  if ((*(byte *)(param_3 + 0xe) & 3) != 3) {
    puVar4 = (ushort *)0x8000000000000002;
    pbVar7 = (byte *)0x0;
    puVar5 = (undefined8 *)0x0;
    puVar8 = (undefined8 *)0x0;
    goto LAB_00005462;
  }
  puVar4 = (ushort *)(**(code **)(param_2 + 8))(param_2,s_Storage_0001a618,&local_res18);
  if ((longlong)puVar4 < 0) goto LAB_0000548e;
  puVar10 = (undefined8 *)FUN_00016b80();
  if (puVar10 == (undefined8 *)0x0) {
LAB_00005234:
    puVar4 = (ushort *)0x8000000000000009;
  }
  else {
    *(undefined4 *)(puVar10 + 3) = 5;
    puVar5 = (undefined8 *)FUN_00016b80();
    local_40 = puVar5;
    if (puVar5 == (undefined8 *)0x0) goto LAB_00005234;
    *(undefined4 *)(puVar5 + 3) = 6;
    puVar6 = FUN_0001880c(*(char **)(param_3 + 0x88));
    FUN_00018744((longlong)puVar5,&DAT_0001a078,(longlong)puVar6);
    puVar6 = FUN_0001880c(*(char **)(param_3 + 0x90));
    FUN_00018744((longlong)puVar5,&DAT_00019eb4,(longlong)puVar6);
    if ((*(byte *)(param_3 + 0xe) & 4) != 0) {
      puVar6 = FUN_0001880c(*(char **)(param_3 + 0x98));
      FUN_00018744((longlong)puVar5,s_Description_00019f20,(longlong)puVar6);
    }
    puVar4 = (ushort *)
             FUN_00004fa0(param_5,(longlong)puVar5,param_4,local_res18,*(char **)(param_3 + 0x88));
    if ((-1 < (longlong)puVar4) &&
       (puVar4 = (ushort *)FUN_0000b428(param_3,(longlong)puVar5,param_6,param_7),
       -1 < (longlong)puVar4)) {
      pbVar7 = FUN_0001784c((longlong)puVar5,0,1,(longlong *)0x0);
      if (pbVar7 == (byte *)0x0) goto LAB_00005234;
      uVar11 = 0;
      bVar1 = *pbVar7;
      while (bVar1 != 0) {
        uVar11 = uVar11 + 1;
        bVar1 = pbVar7[uVar11];
      }
      puVar4 = (ushort *)FUN_00019384(param_1,local_res18,(char *)pbVar7,uVar11,&local_48);
      pbVar3 = local_48;
      puVar8 = (undefined8 *)0x0;
      if (-1 < (longlong)puVar4) {
        puVar8 = FUN_00019714(param_1,local_48);
        if (puVar8 != (undefined8 *)0x0) {
          puVar9 = FUN_000196b0(pbVar3);
          if (puVar9 != (ushort *)0x0) {
            puVar4 = FUN_00004af4(param_1,param_5,(longlong)puVar8,(longlong)puVar10,
                                  (ulonglong)puVar9);
            (**(code **)(DAT_0001e070 + 0x48))(puVar9);
            if ((longlong)puVar4 < 0) goto LAB_00005462;
          }
          puVar4 = FUN_00004d50(param_1,param_5,local_res20,(longlong)puVar8);
          if ((longlong)puVar4 < 0) goto LAB_00005462;
        }
        puVar4 = (ushort *)0x0;
        uVar11 = 0;
        puVar9 = (ushort *)0x0;
        if (*(longlong *)(param_5 + 0x330) != 0) {
          do {
            puVar4 = puVar9;
            lVar2 = *(longlong *)(*(longlong *)(param_5 + 0x338) + uVar11 * 8);
            if (((*(char *)(lVar2 + 0x18) == '\x05') && (*(int *)(lVar2 + 0x100) < 3)) &&
               (puVar4 = (ushort *)
                         FUN_0000492c(param_1,(byte *)(lVar2 + 0x28),pbVar3,(longlong)puVar10),
               puVar5 = local_40, (longlong)puVar4 < 0)) break;
            uVar11 = uVar11 + 1;
            puVar9 = puVar4;
            puVar5 = local_40;
          } while (uVar11 < *(ulonglong *)(param_5 + 0x330));
        }
      }
    }
  }
LAB_00005462:
  if (puVar10 != (undefined8 *)0x0) {
    FUN_00016bcc(puVar10);
  }
  if (puVar5 != (undefined8 *)0x0) {
    FUN_00016bcc(puVar5);
  }
  if (pbVar7 != (byte *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pbVar7);
  }
LAB_0000548e:
  if (local_res18 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (puVar8 != (undefined8 *)0x0) {
    FUN_00016bcc(puVar8);
  }
  return puVar4;
}

