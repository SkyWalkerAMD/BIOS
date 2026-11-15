
ulonglong FUN_0000b14c(longlong param_1,longlong param_2,longlong param_3,short *param_4,
                      longlong param_5)

{
  char cVar1;
  short sVar2;
  longlong lVar3;
  short *psVar4;
  ulonglong uVar5;
  char *pcVar6;
  undefined1 *puVar7;
  undefined1 *puVar8;
  undefined1 *puVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  
  uVar10 = 0;
  sVar2 = *param_4;
  psVar4 = param_4;
  uVar11 = uVar10;
  while (sVar2 != 0) {
    psVar4 = psVar4 + 1;
    uVar11 = uVar11 + 1;
    sVar2 = *psVar4;
  }
  cVar1 = **(char **)(param_3 + 0x88);
  uVar5 = uVar10;
  while (cVar1 != '\0') {
    uVar5 = uVar5 + 1;
    cVar1 = (*(char **)(param_3 + 0x88))[uVar5];
  }
  uVar11 = (uVar5 + uVar11) * 2 + 4;
  pcVar6 = (char *)FUN_00015ad4(uVar11);
  if (pcVar6 == (char *)0x0) {
    return 0x8000000000000009;
  }
  FUN_00015bfc(pcVar6,uVar11,(byte *)u__s__a_0001a130,(ulonglong)param_4);
  puVar7 = FUN_00016b80();
  if (puVar7 != (undefined1 *)0x0) {
    *(undefined4 *)(puVar7 + 0x18) = 5;
    FUN_00018744(param_2,s_StorageControllers_0001ac20,(longlong)puVar7);
    puVar8 = FUN_00016b80();
    if (puVar8 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar8 + 0x18) = 5;
      FUN_00018744(param_2,s_Drives_0001ac14,(longlong)puVar8);
      puVar9 = FUN_00016b80();
      if (puVar9 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar9 + 0x18) = 5;
        FUN_00018744(param_2,s_Volumes_0001ac38,(longlong)puVar9);
        uVar11 = uVar10;
        if (*(longlong *)(param_1 + 0x330) != 0) {
          do {
            lVar3 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar11 * 8);
            if (((*(char *)(lVar3 + 0x18) == '\x04') && (param_5 == *(longlong *)(lVar3 + 0x28))) &&
               ((uVar10 = FUN_00009abc(lVar3 + 0x28,(longlong)puVar7,'\0'), (longlong)uVar10 < 0 ||
                (uVar10 = FUN_00009ccc(param_1,(longlong)puVar8,lVar3 + 0x38,(longlong)puVar9,
                                       (ulonglong)pcVar6), (longlong)uVar10 < 0)))) break;
            uVar11 = uVar11 + 1;
          } while (uVar11 < *(ulonglong *)(param_1 + 0x330));
        }
        goto LAB_0000b2ef;
      }
    }
  }
  uVar10 = 0x8000000000000009;
LAB_0000b2ef:
  (**(code **)(DAT_0001e070 + 0x48))(pcVar6);
  return uVar10;
}

