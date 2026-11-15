
longlong Candidate_CreateControl(longlong param_1,undefined8 param_2,char *param_3)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined1 uVar6;
  bool bVar7;
  longlong lVar8;
  
  uVar6 = DAT_0006b99e;
  uVar5 = DAT_0006b99c;
  uVar4 = DAT_0006b998;
  uVar2 = DAT_0006b990;
  DAT_0006b990._0_2_ = CONCAT11(*(undefined1 *)(param_1 + 0x31),(undefined1)DAT_0006b990);
  uVar3 = DAT_0006b990;
  DAT_0006b990._4_4_ = SUB84(uVar2,4);
  DAT_0006b990._0_4_ = CONCAT13(*(undefined1 *)(param_1 + 0x31),(int3)uVar3);
  uVar3 = DAT_0006b990;
  DAT_0006b990._6_2_ = SUB82(uVar2,6);
  DAT_0006b990._0_6_ = CONCAT15(*(undefined1 *)(param_1 + 0x31),(int5)uVar3);
  DAT_0006b990 = CONCAT17(*(undefined1 *)(param_1 + 0x31),(undefined7)DAT_0006b990);
  DAT_0006b998 = CONCAT31(DAT_0006b998._1_3_,*(undefined1 *)(param_1 + 0x31));
  DAT_0006b99e = *(undefined1 *)(param_1 + 0x31);
  lVar8 = (*(code *)PTR_FUN_0006af38)();
  DAT_0006b990 = uVar2;
  DAT_0006b998 = uVar4;
  DAT_0006b99c = uVar5;
  DAT_0006b99e = uVar6;
  if (((-1 < lVar8) && (*param_3 != '\0')) &&
     (bVar7 = FUN_00016178(param_1,*(int *)(param_1 + 0x3c) - 1), bVar7)) {
    iVar1 = *(int *)(param_1 + 0x3c);
    *param_3 = '\0';
    *(int *)(param_1 + 0x44) = iVar1 + -1;
  }
  return lVar8;
}

