
undefined4 FUN_000110dc(int param_1,void *param_2,size_t param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  ssize_t sVar3;
  int *piVar4;
  char *pcVar5;
  int __errnum;
  
  uVar2 = DAT_00011194;
  uVar1 = DAT_00011190;
  while( true ) {
    if (param_3 == 0) {
      return 0;
    }
    while (sVar3 = read(param_1,param_2,param_3), 0 < sVar3) {
      param_3 = param_3 - sVar3;
      param_2 = (void *)((int)param_2 + sVar3);
      if (param_3 == 0) {
        return 0;
      }
    }
    piVar4 = __errno_location();
    __errnum = *piVar4;
    pcVar5 = strerror(__errnum);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011198,uVar2,uVar1,__errnum,pcVar5);
    if (*piVar4 != 0xb) break;
    FUN_00010fcc(param_1,1);
    param_3 = param_3 - sVar3;
    param_2 = (void *)((int)param_2 + sVar3);
  }
  return 0xffffffff;
}

