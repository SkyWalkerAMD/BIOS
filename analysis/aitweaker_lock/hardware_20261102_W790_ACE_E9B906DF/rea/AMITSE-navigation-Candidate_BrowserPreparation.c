
ulonglong Candidate_BrowserPreparation(undefined8 **param_1,ulonglong param_2)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  longlong *plVar5;
  uint *puVar6;
  ulonglong uVar7;
  ulonglong local_res8;
  undefined8 *local_res10;
  
  uVar7 = 0;
  local_res8 = 0;
  DAT_00092230 = 0;
  uVar1 = FUN_0002a57c(param_1,param_2);
  if (-1 < (longlong)uVar1) {
    uVar4 = 3;
    DAT_0006ac20 = 1;
    DAT_00082648 = 2;
    FUN_00029228((undefined8 *)((longlong)&IMAGE_DOS_HEADER_00000000.e_cblp + 1));
    DAT_0006ac20 = 0;
    DAT_00082648 = 3;
    uVar1 = FUN_00010cc8();
    if (-1 < (longlong)uVar1) {
      DAT_00082648 = 4;
      uVar1 = FUN_00010a94(uVar4,DAT_00082660);
      if (-1 < (longlong)uVar1) {
        uVar4 = 5;
        DAT_0006ac20 = 1;
        DAT_00082648 = 5;
        FUN_00029228((undefined8 *)&IMAGE_DOS_HEADER_00000000.e_cblp);
        DAT_0006ac20 = 2;
        puVar6 = DAT_00092270;
        if (*DAT_00092270 != 0) {
          do {
            plVar5 = (longlong *)((ulonglong)puVar6[uVar7 + 1] + DAT_00092b08);
            if (((plVar5 != (longlong *)0x0) && (*plVar5 != 0)) && (*plVar5 != 0xffff)) {
              FUN_0002e57c(plVar5);
              puVar6 = DAT_00092270;
            }
            uVar7 = uVar7 + 1;
          } while (uVar7 < *puVar6);
        }
        DAT_00092230 = 1;
        FUN_00029228((undefined8 *)((longlong)&IMAGE_DOS_HEADER_00000000.e_cblp + 1));
        FUN_00029228((undefined8 *)&IMAGE_DOS_HEADER_00000000.e_cblp);
        DAT_0006ac20 = 0;
        FUN_00032894();
        puVar2 = FUN_00010f40(5,&local_res8);
        local_res10 = puVar2;
        if (local_res8 < 0x51) {
          puVar3 = FUN_0003eea8(uVar4,0x51);
          if (*(longlong *)(DAT_00082650 + 0x50) != 0) {
            (**(code **)(DAT_000824c8 + 0x160))
                      (puVar3,*(longlong *)(DAT_00082650 + 0x50),
                       *(undefined8 *)(DAT_00082650 + 0x58));
          }
          FUN_000111b4(5,(longlong)puVar3,0x51);
          FUN_00011d48((longlong *)(DAT_00082698 + 0x50),5);
          FUN_00011d48((longlong *)(DAT_00082660 + 0x50),5);
        }
        if (puVar2 != (undefined8 *)0x0) {
          FUN_00005958((longlong *)&local_res10);
        }
        uVar1 = 0;
      }
    }
  }
  DAT_00082648 = 0;
  FUN_000109dc();
  return uVar1;
}

