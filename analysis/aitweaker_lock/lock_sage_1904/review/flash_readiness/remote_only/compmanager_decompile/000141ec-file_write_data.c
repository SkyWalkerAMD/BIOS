
undefined4 file_write_data(char *param_1,void *param_2,long param_3,size_t param_4)

{
  FILE *__stream;
  int iVar1;
  size_t sVar2;
  undefined4 uVar3;
  
  __stream = fopen(param_1,DAT_000142c4);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000142e0,DAT_000142cc,DAT_000142dc,param_1);
    uVar3 = 0xffffffff;
  }
  else {
    iVar1 = fseek(__stream,param_3,0);
    if (iVar1 == 0) {
      sVar2 = fwrite(param_2,1,param_4,__stream);
      if (sVar2 == param_4) {
        fclose(__stream);
        uVar3 = 0;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000142d0,DAT_000142cc,DAT_000142c8);
        fclose(__stream);
        uVar3 = 0xffffffff;
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000142d8,DAT_000142cc,DAT_000142d4,param_3);
      fclose(__stream);
      uVar3 = 0xffffffff;
    }
  }
  return uVar3;
}

