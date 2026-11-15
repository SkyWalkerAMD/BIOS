
void FUN_0004bb6c(void)

{
  uint *puVar1;
  uint *puVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong *plVar6;
  longlong lVar7;
  
  puVar2 = DAT_001937e8;
  uVar4 = 0;
  lVar7 = DAT_001937b0;
  do {
    uVar5 = 0;
    puVar1 = puVar2;
    if (*puVar2 != 0) {
      do {
        plVar6 = (longlong *)((ulonglong)puVar1[1] + DAT_001938e0);
        if ((*(short *)((longlong)plVar6 + 10) == *(short *)((longlong)&DAT_0010c560 + uVar4)) &&
           (((*(longlong *)((longlong)&DAT_0010c568 + uVar4) == 0 ||
             (*plVar6 == *(longlong *)((longlong)&DAT_0010c568 + uVar4))) &&
            (lVar3 = FUN_000b1b20((longlong *)
                                  ((ulonglong)
                                   *(uint *)(lVar7 + 4 + (ulonglong)*(ushort *)(plVar6 + 1) * 4) +
                                  lVar7),(longlong *)(&DAT_0010c550 + uVar4),0x10), lVar3 == 0)))) {
          *(undefined2 *)((longlong)plVar6 + 0x12) = 0;
          lVar7 = DAT_001937b0;
        }
        uVar5 = uVar5 + 1;
        puVar1 = puVar1 + 1;
      } while (uVar5 < *puVar2);
    }
    uVar4 = uVar4 + 0x20;
  } while (uVar4 < 0x120);
  return;
}

