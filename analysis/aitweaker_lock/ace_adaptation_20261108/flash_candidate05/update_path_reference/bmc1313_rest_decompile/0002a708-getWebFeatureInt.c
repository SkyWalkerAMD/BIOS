
undefined4 getWebFeatureInt(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_94;
  char acStack_90 [132];
  
  local_94 = 0;
  memset(acStack_90,0,0x80);
  createIfNotExists(DAT_0002a7d0);
  snprintf(acStack_90,0x80,DAT_0002a7d4,DAT_0002a7d0,param_1);
  puVar1 = (undefined4 *)FCGI_fopen(acStack_90,DAT_0002a7d8);
  if (puVar1 != (undefined4 *)0x0) {
    uVar2 = FCGI_fileno();
    iVar3 = sigwrap_flock(uVar2,2);
    if (iVar3 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0002a7e8,DAT_0002a7e4,DAT_0002a7e0);
      FCGI_fclose(puVar1);
      local_94 = 0xffffffff;
    }
    else {
      __isoc99_fscanf(*puVar1,DAT_0002a7dc,&local_94);
      uVar2 = FCGI_fileno(puVar1);
      sigwrap_flock(uVar2,8);
      FCGI_fclose(puVar1);
    }
  }
  return local_94;
}

