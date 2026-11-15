
void NA06_3f5cc(longlong param_1)

{
  longlong lVar1;
  undefined8 *puVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  uint uVar6;
  ulonglong uVar7;
  uint uVar8;
  uint local_res8 [2];
  
  lVar1 = DAT_000babc0;
  uVar8 = 0;
  local_res8[0] = 0;
  if (DAT_000baaf0 != (uint *)0x0) {
    uVar8 = *DAT_000baaf0;
  }
  lVar4 = DAT_000ba950;
  if (DAT_000ba950 != 0) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    DAT_000ba950 = 0;
  }
  DAT_000ba958 = 0;
  puVar2 = FUN_00059b50(lVar4,(ulonglong)(uint)(DAT_000ba9c8 + DAT_000ba9b8 + DAT_000ba9d8));
  (**(code **)(DAT_000afbc8 + 0x160))
            (puVar2,DAT_000babc0,DAT_000ba9c8 + DAT_000ba9b8 + DAT_000ba9d8);
  DAT_000afd88 = 1;
  if ((DAT_000babc0 != 0) && (uVar7 = 0, lVar4 = DAT_000babc0, uVar8 != 0)) {
    do {
      plVar5 = (longlong *)
               ((ulonglong)*(uint *)((longlong)puVar2 + uVar7 * 4 + 4) + (longlong)puVar2);
      if ((plVar5 != (longlong *)0x0) && ((*plVar5 != 0 && (*plVar5 != 0xffff)))) {
        if (lVar1 == lVar4) {
          plVar5 = (longlong *)((ulonglong)DAT_000baaf0[uVar7 + 1] + lVar4);
        }
        else {
          plVar5 = FUN_0003f578(plVar5);
        }
        if (((plVar5 != (longlong *)0x0) && (*plVar5 != 0)) && (*plVar5 != 0xffff)) {
          DAT_000ba9e8 = (int)uVar7;
          lVar3 = NA06_3f414((longlong)plVar5,param_1,local_res8);
          lVar4 = DAT_000babc0;
          if (lVar3 == -0x7ffffffffffffffa) {
            uVar7 = (ulonglong)((int)uVar7 - 1);
          }
          else {
            local_res8[0] = 0;
            DAT_000ba9e8 = 0xffff;
          }
        }
      }
      uVar6 = (int)uVar7 + 1;
      uVar7 = (ulonglong)uVar6;
    } while (uVar6 < uVar8);
  }
  if ((param_1 - 2U < 2) && (DAT_000ba958 != 0)) {
    uVar7 = 0;
    if (DAT_000ba958 != 0) {
      do {
        NA06_3f7c0(*(longlong *)(DAT_000ba950 + uVar7 * 8),3);
        NA06_3f7c0(*(longlong *)(DAT_000ba950 + uVar7 * 8),2);
        uVar7 = uVar7 + 1;
      } while (uVar7 < DAT_000ba958);
    }
    if (DAT_000ba950 != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
      DAT_000ba950 = 0;
    }
    DAT_000ba958 = 0;
  }
  DAT_000afd88 = 0;
  if (puVar2 != (undefined8 *)0x0) {
    (**(code **)(DAT_000afbc8 + 0x48))(puVar2);
  }
  return;
}

