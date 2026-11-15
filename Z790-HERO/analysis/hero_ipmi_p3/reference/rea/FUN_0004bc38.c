
void FUN_0004bc38(void)

{
  longlong lVar1;
  longlong *plVar2;
  ulonglong uVar3;
  uint *puVar4;
  ulonglong uVar5;
  longlong lVar6;
  
  uVar5 = 0;
  puVar4 = DAT_001937e8;
  lVar6 = DAT_001937b0;
  do {
    uVar3 = 0;
    if (*puVar4 != 0) {
      do {
        plVar2 = (longlong *)((ulonglong)puVar4[uVar3 + 1] + DAT_001938e0);
        if ((*(short *)((longlong)plVar2 + 10) == *(short *)((longlong)&DAT_0010c770 + uVar5)) &&
           ((*(longlong *)((longlong)&DAT_0010c778 + uVar5) == 0 ||
            (*plVar2 == *(longlong *)((longlong)&DAT_0010c778 + uVar5))))) {
          lVar1 = FUN_000b1b20((longlong *)
                               ((ulonglong)
                                *(uint *)(lVar6 + 4 + (ulonglong)*(ushort *)(plVar2 + 1) * 4) +
                               lVar6),(longlong *)(&DAT_0010c760 + uVar5),0x10);
          if (lVar1 == 0) {
            if ((*(byte *)((longlong)plVar2 + 0x14) & 0x20) != 0) {
              FUN_0003644c();
              puVar4 = DAT_001937e8;
            }
            *(uint *)((longlong)plVar2 + 0x14) = *(uint *)((longlong)plVar2 + 0x14) & 0xffffffdf | 1
            ;
            lVar6 = DAT_001937b0;
          }
        }
        uVar3 = uVar3 + 1;
      } while (uVar3 < *puVar4);
    }
    uVar5 = uVar5 + 0x20;
  } while (uVar5 < 0xe0);
  return;
}

