
undefined8 FUN_00031f6c(longlong *param_1)

{
  bool bVar1;
  longlong lVar2;
  char *pcVar3;
  longlong lVar4;
  
  lVar2 = 0;
  *(undefined2 *)(param_1 + 2) = 0;
  *(undefined2 *)((longlong)param_1 + 0x22) = 0;
  pcVar3 = (char *)(*param_1 + 4);
  bVar1 = true;
  do {
    lVar4 = lVar2;
    if (*pcVar3 == ')') {
      if (lVar2 != 0) {
        lVar4 = lVar2 + -1;
      }
    }
    else if (*pcVar3 == '_') {
      if (pcVar3[0x12] == '\x03') {
        *(undefined2 *)(param_1 + 2) = *(undefined2 *)(pcVar3 + 0x13);
      }
      else if (pcVar3[0x12] == '\x04') {
        bVar1 = false;
        *(undefined2 *)((longlong)param_1 + 0x22) = *(undefined2 *)(pcVar3 + 0x13);
      }
    }
    lVar2 = lVar4 + 1;
    if ((byte)pcVar3[1] < 0x80) {
      lVar2 = lVar4;
    }
    pcVar3 = pcVar3 + ((byte)pcVar3[1] & 0x7f);
  } while ((bVar1) && (0 < lVar2));
  return 0;
}

