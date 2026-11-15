
int FUN_180003ff0(ulonglong param_1)

{
  char cVar1;
  int iVar2;
  ulonglong in_RAX;
  ulonglong uVar3;
  
  uVar3 = in_RAX & 0xffffffffffffff00;
  do {
    iVar2 = (int)uVar3;
    if ((param_1 & 1) != 0) break;
    cVar1 = (char)uVar3 + '\x01';
    uVar3 = CONCAT71((int7)(uVar3 >> 8),cVar1);
    iVar2 = (int)uVar3;
    param_1 = param_1 >> 1 & 0x7fffffff;
  } while (cVar1 < '\x1a');
  return iVar2 + 0x41;
}

