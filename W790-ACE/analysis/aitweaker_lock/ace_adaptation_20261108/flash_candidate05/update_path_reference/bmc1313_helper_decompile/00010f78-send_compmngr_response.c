
undefined4 send_compmngr_response(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  iVar2 = sigwrap_open(DAT_00010fdc,1);
  iVar1 = DAT_00010fe0;
  if (iVar2 == -1) {
    perror(DAT_00010fe8);
    uVar4 = 0xffffffff;
  }
  else {
    iVar3 = sigwrap_write(iVar2,param_1,DAT_00010fe0);
    if (iVar3 != iVar1) {
      perror(DAT_00010fe4);
    }
    sigwrap_close(iVar2);
    uVar4 = 0;
  }
  return uVar4;
}

