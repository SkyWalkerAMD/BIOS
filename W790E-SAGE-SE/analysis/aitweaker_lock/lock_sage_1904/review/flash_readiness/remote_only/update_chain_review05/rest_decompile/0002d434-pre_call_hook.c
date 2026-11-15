
void pre_call_hook(void)

{
  int iVar1;
  
  iVar1 = ReadPipeData();
  if (iVar1 < 0) {
    FCGI_fprintf(DAT_0002d490,DAT_0002d494);
  }
  if (*(int *)(DAT_0002d488 + 0x1e4) != 1) {
    return;
  }
  iVar1 = ReadCmdPipeData();
  if (iVar1 < 1) {
    return;
  }
  FCGI_fprintf(DAT_0002d490,DAT_0002d48c);
  WebSession_Terminate(iVar1);
  return;
}

