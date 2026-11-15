
undefined4 write_forcedUpdate_flag(void)

{
  FILE *__stream;
  
  __stream = fopen(DAT_00013fa0,DAT_00013f9c);
  if (__stream != (FILE *)0x0) {
    fputc(0x31,__stream);
    fclose(__stream);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fa4,DAT_00013fa0);
  return 0xffffffff;
}

