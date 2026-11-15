
undefined4 FUN_000133cc(int param_1)

{
  int iVar1;
  char *pcVar2;
  char cVar3;
  
  if (param_1 < *(int *)(DAT_00013480 + 0x10)) {
    cVar3 = '\0';
    iVar1 = *(int *)(DAT_00013484 + param_1 * 4);
    *(undefined1 *)(iVar1 + 0x13) = 0x80;
    *(undefined1 *)(iVar1 + 0x38) = 0;
    *(undefined1 *)(iVar1 + 0x39) = 0;
    *(undefined1 *)(iVar1 + 0x3a) = 0;
    *(undefined1 *)(iVar1 + 0x3b) = 0;
    *(undefined1 *)(iVar1 + 0x3c) = 0;
    *(undefined1 *)(iVar1 + 0xd) = 0;
    *(undefined1 *)(iVar1 + 0xe) = 0;
    *(undefined1 *)(iVar1 + 0xf) = 0;
    *(undefined1 *)(iVar1 + 0x35) = 1;
    *(undefined1 *)(iVar1 + 0x36) = 2;
    *(undefined1 *)(iVar1 + 0x37) = 0x3a;
    *(undefined1 *)(iVar1 + 0xc) = 0x1d;
    pcVar2 = (char *)(iVar1 + -1);
    do {
      pcVar2 = pcVar2 + 1;
      cVar3 = cVar3 + *pcVar2;
    } while ((char *)(iVar1 + 0x1f) != pcVar2);
    *(char *)(iVar1 + 0xb) = -cVar3;
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013490,DAT_0001348c,DAT_00013488);
  return 1;
}

