
undefined4 read_file(char *param_1,undefined4 *param_2,size_t *param_3)

{
  FILE *__stream;
  char *__format;
  size_t __size;
  void *__ptr;
  size_t sVar1;
  
  __stream = fopen(param_1,(char *)(DAT_00012718 + 0x12690));
  if (__stream == (FILE *)0x0) {
    __format = (char *)(DAT_0001271c + 0x126a8);
  }
  else {
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
    __format = (char *)(DAT_00012720 + 0x12704);
  }
  printf(__format,param_1);
                    /* WARNING: Subroutine does not return */
  exit(1);
}

