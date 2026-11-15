
void WS05_1578(void)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
  uVar3 = 0;
  DAT_00005b81 = 1;
  DAT_00005b83 = 0;
  do {
    iVar1 = (*(code *)(&PTR_FUN_000053b0)[uVar3 * 6])
                      ((&DAT_000053b8)[uVar3 * 0xc],(&DAT_000053bc)[uVar3 * 0xc]);
    if (iVar1 == 1) {
      do {
        uVar3 = (ulonglong)((int)uVar3 + 1);
      } while ((code *)(&PTR_FUN_000053b0)[uVar3 * 6] != FUN_00001b58);
    }
    uVar2 = (int)uVar3 + 1;
    uVar3 = (ulonglong)uVar2;
  } while (uVar2 == 0);
  return;
}

