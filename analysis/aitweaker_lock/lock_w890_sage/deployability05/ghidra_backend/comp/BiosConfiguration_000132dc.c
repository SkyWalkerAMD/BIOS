
undefined4 BiosConfiguration(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  
  iVar5 = DAT_000133ac + 0x13300;
  iVar1 = dlopen(DAT_000133a8 + 0x132fc,1);
  if ((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_000133b0 + 0x1332c), pcVar2 == (code *)0x0))
  {
    uVar6 = 0xffffffff;
  }
  else {
    uVar3 = sigwrap_open(*(undefined4 *)(iVar5 + DAT_000133b4),2);
    uVar4 = sigwrap_open(DAT_000133b8 + 0x13360,2);
    uVar6 = (*pcVar2)(uVar3,uVar4,param_1,*(undefined4 *)(iVar5 + DAT_000133bc),
                      *(undefined4 *)(iVar5 + DAT_000133c0));
    sigwrap_close(uVar3);
    sigwrap_close(uVar4);
  }
  dlclose(iVar1);
  return uVar6;
}

