
undefined8 FUN_000096a8(longlong param_1,longlong param_2,short *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  short *psVar3;
  char *pcVar4;
  undefined1 *puVar5;
  undefined8 uVar6;
  longlong lVar7;
  
  lVar7 = 0;
  if ((param_1 == 0) || (param_2 == 0)) {
    uVar6 = 0x8000000000000002;
  }
  else {
    if ((param_3 != (short *)0x0) && (lVar2 = lVar7, psVar3 = param_3, *param_3 != 0)) {
      do {
        psVar3 = psVar3 + 1;
        lVar2 = lVar2 + 1;
      } while (*psVar3 != 0);
      psVar3 = param_3;
      if (lVar2 != 0) {
        do {
          psVar3 = psVar3 + 1;
          lVar7 = lVar7 + 1;
        } while (*psVar3 != 0);
        uVar1 = lVar7 * 2 + 2;
        pcVar4 = (char *)FUN_00015ad4(uVar1);
        if (pcVar4 != (char *)0x0) {
          FUN_00015c2c(pcVar4,uVar1,&DAT_0001b550,(ulonglong)param_3);
          puVar5 = FUN_0001880c(pcVar4);
          FUN_00018744(param_2,s_UefiDevicePath_0001b558,(longlong)puVar5);
          (**(code **)(DAT_0001e070 + 0x48))(pcVar4);
        }
      }
    }
    puVar5 = FUN_0001880c(*(char **)(param_1 + 0x338));
    FUN_00018744(param_2,&DAT_0001a078,(longlong)puVar5);
    if ((*(byte *)(param_1 + 0x185) & 1) == 0) {
      pcVar4 = *(char **)(param_1 + 0x338);
    }
    else {
      pcVar4 = *(char **)(param_1 + 0x348);
    }
    puVar5 = FUN_0001880c(pcVar4);
    FUN_00018744(param_2,&DAT_00019eb4,(longlong)puVar5);
    uVar6 = FUN_00003dc4(*(byte *)(param_1 + 0x185) >> 7,*(byte *)(param_1 + 0x185) >> 5 & 1,
                         (int *)(param_1 + 0x10c),param_2);
  }
  return uVar6;
}

