
undefined4 read_file_append(char *param_1,char *param_2,int *param_3,size_t *param_4)

{
  int iVar1;
  FILE *__stream;
  uint __n;
  void *pvVar2;
  size_t sVar3;
  FILE *__stream_00;
  size_t sVar4;
  undefined4 uVar5;
  uint __size;
  
  iVar1 = access(param_1,0);
  if (iVar1 == 0) {
    __stream = fopen(param_1,DAT_000132d8);
    if (__stream == (FILE *)0x0) {
      printf(DAT_000132f8,param_1);
      return 0xffffffff;
    }
    fseek(__stream,0,2);
    __n = ftell(__stream);
    rewind(__stream);
    iVar1 = access(param_2,0);
    if ((__n & 0xffffefff) == 0 && iVar1 == 0) goto LAB_000131d4;
    sVar4 = 0;
    __stream_00 = (FILE *)0x0;
    __size = __n;
  }
  else {
    iVar1 = access(param_2,0);
    if (iVar1 != 0) {
      printf(DAT_000132dc,0);
      printf(DAT_000132e4,0);
      return 0xffffffff;
    }
    __n = 0;
    __stream = (FILE *)0x0;
LAB_000131d4:
    __stream_00 = fopen(param_2,DAT_000132d8);
    if (__stream_00 == (FILE *)0x0) {
      printf(DAT_000132f8,param_2);
      uVar5 = 0xffffffff;
      goto LAB_00013174;
    }
    fseek(__stream_00,0,2);
    sVar4 = ftell(__stream_00);
    __size = sVar4 + __n;
    rewind(__stream_00);
  }
  printf(DAT_000132dc,__n,sVar4);
  if ((__size + 0xfdfff000 & 0xfdffffff) == 0) {
    pvVar2 = malloc(__size);
    *param_3 = (int)pvVar2;
    if (pvVar2 == (void *)0x0) {
      printf(DAT_000132f0,__size);
      uVar5 = 0xffffffff;
    }
    else {
      iVar1 = access(param_1,0);
      if ((iVar1 == 0) && (sVar3 = fread((void *)*param_3,1,__n,__stream), sVar3 != __n)) {
        printf(DAT_000132ec,param_1);
        uVar5 = 0xffffffff;
      }
      else {
        iVar1 = access(param_2,0);
        if (iVar1 == 0) {
          if (__n == 0x1000) {
            sVar3 = fread((void *)(*param_3 + 0x1000),1,sVar4,__stream_00);
            if (sVar3 == sVar4) goto LAB_0001314c;
            printf(DAT_000132f4,param_2);
            uVar5 = 0xffffffff;
          }
          else {
            if ((__n != 0) ||
               (sVar4 = fread((void *)*param_3,1,__size,__stream_00), sVar4 == __size))
            goto LAB_0001314c;
            printf(DAT_000132e8,param_2);
            uVar5 = 0xffffffff;
          }
        }
        else {
LAB_0001314c:
          *param_4 = __size;
          printf(DAT_000132e0,__size);
          uVar5 = 0;
        }
      }
    }
  }
  else {
    printf(DAT_000132e4,__size);
    uVar5 = 0xffffffff;
  }
  if (__stream_00 != (FILE *)0x0) {
    fclose(__stream_00);
  }
LAB_00013174:
  if (__stream == (FILE *)0x0) {
    return uVar5;
  }
  fclose(__stream);
  return uVar5;
}

