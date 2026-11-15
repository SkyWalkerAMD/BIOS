
longlong Candidate_ACEDxe_ExitBootServices(undefined8 param_1,ulonglong param_2,undefined **param_3)

{
  longlong lVar1;
  undefined **ppuVar2;
  longlong lVar3;
  longlong *plVar4;
  
  DAT_00017af0 = param_2 == DAT_00017ae0;
  lVar3 = 0;
  if (DAT_00015cc0 != '\0') {
    Candidate_ACEDxe_NotifySignalList((longlong *)&DAT_00015af0);
    Candidate_ACEDxe_NotifySignalList((longlong *)&DAT_00015c20);
    (**(code **)(DAT_00017ab8 + 8))(DAT_00017ab8,0);
    Candidate_ACEDxe_NotifySignalList(&DAT_00015be0);
    DAT_00015cc0 = '\0';
  }
  FUN_0000e6ec((ulonglong *)&DAT_00016e38);
  if ((DAT_00017af0 == '\0') || (param_2 < DAT_00017ae8)) {
LAB_0000267a:
    lVar3 = -0x7ffffffffffffffe;
  }
  else {
    param_3 = &PTR_LOOP_00016e28;
    for (ppuVar2 = (undefined **)PTR_LOOP_00016e28; ppuVar2 != &PTR_LOOP_00016e28;
        ppuVar2 = (undefined **)*ppuVar2) {
      if (((*(int *)((longlong)ppuVar2 + 0x14) < 0x10) &&
          ((&DAT_00016689)[(longlong)*(int *)((longlong)ppuVar2 + 0x14) * 0x30] != '\0')) &&
         ((((ulonglong)ppuVar2[3] & 0xfff) != 0 || (((ulonglong)(ppuVar2[4] + 1) & 0xfff) != 0))))
      goto LAB_0000267a;
    }
  }
  DAT_00016e48._0_4_ = 1;
  Candidate_ACEDxe_RestoreTpl(DAT_00016e40);
  if (lVar3 < 0) {
    Candidate_ACEDxe_NotifySignalList((longlong *)&DAT_000159c0);
  }
  else {
    DAT_00017a98 = 1;
    FUN_000111b8(1,0x3101019,param_3,&DAT_00015c80,0);
    if ((DAT_0001f540 != 0) &&
       (plVar4 = *(longlong **)PTR_LOOP_00015d48, plVar4 != (longlong *)PTR_LOOP_00015d48)) {
      do {
        FUN_00008bbc(plVar4[-4],(-plVar4[-3] & 0xfffU) + plVar4[-3],0);
        plVar4 = (longlong *)*plVar4;
      } while (plVar4 != (longlong *)PTR_LOOP_00015d48);
    }
    (**(code **)(DAT_00017ac0 + 0x10))(DAT_00017ac0);
    lVar1 = DAT_00017a68;
    *(undefined8 *)(DAT_00017a68 + 0x60) = 0;
    *(undefined8 *)(lVar1 + 0x30) = 0;
    *(undefined8 *)(lVar1 + 0x28) = 0;
    *(undefined8 *)(lVar1 + 0x40) = 0;
    *(undefined8 *)(lVar1 + 0x38) = 0;
    *(undefined8 *)(lVar1 + 0x50) = 0;
    *(undefined8 *)(lVar1 + 0x48) = 0;
    FUN_0000256c(lVar1);
    FUN_00000490(DAT_00017bb0,0x178);
    DAT_00017bb0 = (undefined8 *)0x0;
    PTR_LOOP_00015d48[0x49] = 1;
  }
  return lVar3;
}

