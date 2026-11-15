
undefined4 get_bios_file_size(long *param_1)

{
  char *pcVar1;
  FILE *__stream;
  int iVar2;
  long lVar3;
  undefined4 uVar4;
  
  pcVar1 = DAT_00011070;
  __stream = fopen(DAT_00011070,DAT_00011074);
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011080,DAT_00011078,0x2b,pcVar1);
    uVar4 = 0xffffffff;
  }
  else {
    iVar2 = fseek(__stream,0,2);
    if (iVar2 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001107c,DAT_00011078,0x31);
      fclose(__stream);
      uVar4 = 0xffffffff;
    }
    else {
      lVar3 = ftell(__stream);
      *param_1 = lVar3;
      iVar2 = fseek(__stream,0,0);
      if (iVar2 == -1) {
        fclose(__stream);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001107c,DAT_00011078,0x3a);
        uVar4 = 0xffffffff;
      }
      else {
        fclose(__stream);
        uVar4 = 0;
      }
    }
  }
  return uVar4;
}

