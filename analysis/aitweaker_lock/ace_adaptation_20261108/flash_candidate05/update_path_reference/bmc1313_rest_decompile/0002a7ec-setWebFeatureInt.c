
undefined4 setWebFeatureInt(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  char acStack_90 [128];
  
  memset(acStack_90,0,0x80);
  createIfNotExists(DAT_0002a8b8);
  snprintf(acStack_90,0x80,DAT_0002a8bc,DAT_0002a8b8,param_1);
  iVar1 = FCGI_fopen(acStack_90,DAT_0002a8c0);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = FCGI_fileno();
    sigwrap_flock(uVar2,2);
    FCGI_fprintf(iVar1,DAT_0002a8c4,param_2);
    uVar2 = FCGI_fileno(iVar1);
    iVar3 = sigwrap_flock(uVar2,8);
    if (iVar3 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0002a8cc,DAT_0002a8c8,0x198);
      FCGI_fclose(iVar1);
      uVar2 = 0xffffffff;
    }
    else {
      FCGI_fclose(iVar1);
      uVar2 = 0;
    }
  }
  return uVar2;
}

