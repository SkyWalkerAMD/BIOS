
undefined4 read_file(char *param_1,undefined4 *param_2,size_t *param_3)

{
  FILE *__stream;
  size_t __size;
  void *__ptr;
  size_t sVar1;
  
  __stream = fopen(param_1,DAT_00013038);
  if (__stream == (FILE *)0x0) {
    printf(DAT_0001303c,param_1);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fseek(__stream,0,2);
  __size = ftell(__stream);
  rewind(__stream);
  __ptr = malloc(__size);
  *param_2 = __ptr;
  sVar1 = fread(__ptr,1,__size,__stream);
  if (sVar1 == __size) {
    *param_3 = sVar1;
    fclose(__stream);
    return 0;
  }
  printf(DAT_00013040,param_1);
                    /* WARNING: Subroutine does not return */
  exit(1);
}

