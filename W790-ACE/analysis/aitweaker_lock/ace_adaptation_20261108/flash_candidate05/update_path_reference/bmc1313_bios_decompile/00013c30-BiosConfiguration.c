
undefined4 BiosConfiguration(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  iVar1 = dlopen(DAT_00013ccc,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_00013cd0), pcVar2 == (code *)0x0)) {
    uVar5 = 0xffffffff;
  }
  else {
    uVar3 = sigwrap_open(DAT_00013cd4,2);
    uVar4 = sigwrap_open(DAT_00013cd8,2);
    uVar5 = (*pcVar2)(uVar3,uVar4,param_1,DAT_00013ce0,DAT_00013cdc);
    sigwrap_close(uVar3);
    sigwrap_close(uVar4);
  }
  dlclose(iVar1);
  return uVar5;
}

