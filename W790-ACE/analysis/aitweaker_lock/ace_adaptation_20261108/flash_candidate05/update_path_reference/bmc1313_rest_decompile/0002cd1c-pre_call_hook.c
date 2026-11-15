
void pre_call_hook(void)

{
  int iVar1;
  
  iVar1 = ReadPipeData();
  if (iVar1 < 0) {
    FCGI_fprintf(DAT_0002cd78,DAT_0002cd7c);
  }
  if (*(int *)(DAT_0002cd70 + 0x1e0) != 1) {
    return;
  }
  iVar1 = ReadCmdPipeData();
  if (iVar1 < 1) {
    return;
  }
  FCGI_fprintf(DAT_0002cd78,DAT_0002cd74);
  WebSession_Terminate(iVar1);
  return;
}

