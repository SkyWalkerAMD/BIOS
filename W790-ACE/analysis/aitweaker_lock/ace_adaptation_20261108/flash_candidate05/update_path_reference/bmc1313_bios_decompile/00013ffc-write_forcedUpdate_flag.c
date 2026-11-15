
undefined4 write_forcedUpdate_flag(void)

{
  FILE *__stream;
  
  __stream = fopen(DAT_0001404c,DAT_00014048);
  if (__stream != (FILE *)0x0) {
    fputc(0x31,__stream);
    fclose(__stream);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00014050,DAT_0001404c);
  return 0xffffffff;
}

