
int SwitchGPIO(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013248,DAT_00013244,0xa9,DAT_00013240,param_1);
  iVar1 = dlopen(DAT_0001324c,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013250), pcVar2 == (code *)0x0)) {
    iVar4 = -1;
  }
  else {
    iVar3 = (*pcVar2)(param_1);
    iVar4 = 0;
    if (iVar3 != 0) {
      dlclose(iVar1);
      puts(DAT_00013254);
      return iVar3;
    }
  }
  dlclose(iVar1);
  return iVar4;
}

