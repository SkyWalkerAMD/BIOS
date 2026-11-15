
void FUN_00011244(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  piVar1 = DAT_000112cc;
  IDBG_LINUXAPP_DbgOut(0x86,DAT_000112d0);
  iVar2 = DAT_000112d4;
  if (0 < *piVar1) {
    iVar4 = 0;
    iVar3 = DAT_000112d4;
    do {
      if (*(code **)(iVar3 + 0x108) != (code *)0x0) {
        (**(code **)(iVar3 + 0x108))();
      }
      iVar4 = iVar4 + 1;
      iVar3 = iVar3 + 0x114;
    } while (iVar4 < *piVar1);
    if (0 < *piVar1) {
      iVar3 = 0;
      do {
        if (*(code **)(iVar2 + 0x108) != (code *)0x0) {
          (**(code **)(iVar2 + 0x108))();
        }
        iVar3 = iVar3 + 1;
        iVar2 = iVar2 + 0x114;
      } while (iVar3 < *piVar1);
    }
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}

