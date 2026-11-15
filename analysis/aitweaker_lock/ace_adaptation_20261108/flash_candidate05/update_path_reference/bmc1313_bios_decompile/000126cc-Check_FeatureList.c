
undefined1 Check_FeatureList(void)

{
  FILE *__stream;
  undefined1 uStack_20;
  undefined1 local_1f;
  
  __stream = fopen(DAT_00012718,DAT_00012714);
  if (__stream == (FILE *)0x0) {
    local_1f = 1;
  }
  else {
    fread(&uStack_20,0x15,1,__stream);
    fclose(__stream);
  }
  return local_1f;
}

