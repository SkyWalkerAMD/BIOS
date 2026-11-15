
undefined4 BiosConfiguration(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  iVar1 = dlopen(DAT_00013c24,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013c28), pcVar2 == (code *)0x0)) {
    uVar5 = 0xffffffff;
  }
  else {
    uVar3 = sigwrap_open(DAT_00013c2c,2);
    uVar4 = sigwrap_open(DAT_00013c30,2);
    uVar5 = (*pcVar2)(uVar3,uVar4,param_1,DAT_00013c38,DAT_00013c34);
    sigwrap_close(uVar3);
    sigwrap_close(uVar4);
  }
  dlclose(iVar1);
  return uVar5;
}

