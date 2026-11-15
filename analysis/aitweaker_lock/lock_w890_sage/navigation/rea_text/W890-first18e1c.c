
ulonglong Observed_FirstPageInitialization(uint *param_1,ulonglong param_2)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  longlong *plVar5;
  uint *puVar6;
  ulonglong uVar7;
  ulonglong local_res8;
  
  uVar7 = 0;
  local_res8 = 0;
  DAT_000baab0 = 0;
  uVar1 = FUN_00040d94(param_1,param_2);
  if (-1 < (longlong)uVar1) {
    uVar4 = 3;
    DAT_00093aa0 = 1;
    DAT_000afcd0 = 2;
    FUN_0003f5cc(3);
    DAT_00093aa0 = 0;
    DAT_000afcd0 = 3;
    uVar1 = FUN_0001c3c8();
    if (-1 < (longlong)uVar1) {
      DAT_000afcd0 = 4;
      uVar1 = FUN_0001c17c(uVar4,DAT_000afce8);
      if (-1 < (longlong)uVar1) {
        uVar4 = 5;
        DAT_00093aa0 = 1;
        DAT_000afcd0 = 5;
        FUN_0003f5cc(2);
        DAT_00093aa0 = 2;
        puVar6 = DAT_000baaf0;
        if (*DAT_000baaf0 != 0) {
          do {
            plVar5 = (longlong *)((ulonglong)puVar6[uVar7 + 1] + DAT_000babc0);
            if (((plVar5 != (longlong *)0x0) && (*plVar5 != 0)) && (*plVar5 != 0xffff)) {
              FUN_00045614(plVar5);
              puVar6 = DAT_000baaf0;
            }
            uVar7 = uVar7 + 1;
          } while (uVar7 < *puVar6);
        }
        DAT_000baab0 = 1;
        FUN_0003f5cc(3);
        FUN_0003f5cc(2);
        DAT_00093aa0 = 0;
        FUN_00049c1c();
        puVar2 = FUN_0001c6d0(5,&local_res8);
        if (local_res8 < 0x51) {
          puVar3 = FUN_00059b50(uVar4,0x51);
          if (*(longlong *)(DAT_000afcd8 + 0x50) != 0) {
            (**(code **)(DAT_000afbc8 + 0x160))
                      (puVar3,*(longlong *)(DAT_000afcd8 + 0x50),
                       *(undefined8 *)(DAT_000afcd8 + 0x58));
          }
          Candidate_ConfigCommit(5,(longlong)puVar3,0x51);
          FUN_0001d540((longlong *)(DAT_000afd20 + 0x50),5);
          FUN_0001d540((longlong *)(DAT_000afce8 + 0x50),5);
        }
        if (puVar2 != (undefined8 *)0x0) {
          (**(code **)(DAT_000afbc8 + 0x48))(puVar2);
        }
        uVar1 = 0;
      }
    }
  }
  DAT_000afcd0 = 0;
  FUN_0001c078();
  return uVar1;
}

