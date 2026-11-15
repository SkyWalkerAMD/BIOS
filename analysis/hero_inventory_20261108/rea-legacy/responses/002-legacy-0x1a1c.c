
longlong FUN_00001814(longlong param_1,byte *param_2,longlong param_3)

{
  int iVar1;
  longlong lVar2;
  longlong *plVar3;
  undefined1 *puVar4;
  undefined1 *puVar5;
  longlong *plVar6;
  longlong lVar7;
  longlong lVar8;
  char *pcVar9;
  undefined1 *puVar10;
  ulonglong uVar11;
  
  lVar7 = 0;
  uVar11 = 0;
  puVar4 = FUN_00016b80();
  if (puVar4 == (undefined1 *)0x0) {
LAB_00001a3d:
    lVar7 = -0x7ffffffffffffff7;
  }
  else {
    *(undefined4 *)(puVar4 + 0x18) = 5;
    FUN_00018744(param_3,s_Slots_0001a070,(longlong)puVar4);
    puVar5 = FUN_0001880c(*(char **)(param_2 + 8));
    FUN_00018744(param_3,&DAT_0001a078,(longlong)puVar5);
    puVar5 = FUN_0001880c(*(char **)(param_2 + 0x10));
    FUN_00018744(param_3,&DAT_00019eb4,(longlong)puVar5);
    if ((*param_2 & 4) != 0) {
      puVar5 = FUN_0001880c(*(char **)(param_2 + 0x18));
      FUN_00018744(param_3,s_Description_00019f20,(longlong)puVar5);
    }
    if (*(longlong *)(param_1 + 0x330) != 0) {
      do {
        lVar2 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar11 * 8);
        if ((((*(char *)(lVar2 + 0x18) == '\n') && ((*(byte *)(lVar2 + 0x48) & 2) != 0)) &&
            (*(char *)(lVar2 + 0x34) != -1)) && ((*(byte *)(lVar2 + 0x48) & 0xfd) != 0)) {
          puVar5 = FUN_00016b80();
          if (puVar5 == (undefined1 *)0x0) goto LAB_00001a3d;
          *(undefined4 *)(puVar5 + 0x18) = 6;
          plVar3 = *(longlong **)(puVar4 + 0x10);
          if (*(longlong **)(puVar4 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(puVar4 + 0x10) = puVar5;
          }
          else {
            do {
              plVar6 = plVar3;
              plVar3 = (longlong *)*plVar6;
            } while ((longlong *)*plVar6 != (longlong *)0x0);
            *plVar6 = (longlong)puVar5;
            *(longlong **)(puVar5 + 8) = plVar6;
          }
          lVar7 = FUN_00003dc4(*(byte *)(lVar2 + 0x48) & 1,'\0',(int *)(lVar2 + 0x28),
                               (longlong)puVar5);
          if (lVar7 < 0) {
            return lVar7;
          }
          if ((*(byte *)(lVar2 + 0x48) & 4) != 0) {
            lVar8 = FUN_000187b4((uint)*(byte *)(lVar2 + 0x35));
            FUN_00018744((longlong)puVar5,s_HotPluggable_0001a080,lVar8);
          }
          if ((*(byte *)(lVar2 + 0x48) & 8) != 0) {
            lVar8 = FUN_000187d8(*(undefined8 *)(lVar2 + 0x38));
            FUN_00018744((longlong)puVar5,s_Lanes_0001a090,lVar8);
          }
          if ((*(byte *)(lVar2 + 0x48) & 0x10) != 0) {
            pcVar9 = FUN_00000c1c(*(int *)(lVar2 + 0x40));
            puVar10 = FUN_0001880c(pcVar9);
            FUN_00018744((longlong)puVar5,s_PCIeType_00019dd0,(longlong)puVar10);
          }
          if ((*(byte *)(lVar2 + 0x48) & 0x20) != 0) {
            iVar1 = *(int *)(lVar2 + 0x44);
            if (iVar1 == 0) {
              pcVar9 = s_FullLength_00019d60;
            }
            else if (iVar1 == 1) {
              pcVar9 = s_HalfLength_00019d70;
            }
            else if (iVar1 == 2) {
              pcVar9 = s_LowProfile_00019d80;
            }
            else if (iVar1 == 3) {
              pcVar9 = &DAT_00019d8c;
            }
            else if (iVar1 == 4) {
              pcVar9 = &DAT_00019d94;
            }
            else {
              pcVar9 = &DAT_00019d98;
            }
            puVar10 = FUN_0001880c(pcVar9);
            FUN_00018744((longlong)puVar5,s_SlotType_0001a098,(longlong)puVar10);
          }
        }
        uVar11 = uVar11 + 1;
      } while (uVar11 < *(ulonglong *)(param_1 + 0x330));
    }
  }
  return lVar7;
}

