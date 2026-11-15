
uint PDK_ASUSBIOSConfiguration(int param_1,int param_2,undefined4 param_3,int param_4,int param_5)

{
  char *pcVar1;
  void *__ptr;
  void *__ptr_00;
  uint uVar2;
  size_t sVar3;
  char *__format;
  char *__format_00;
  int iVar4;
  int __offset;
  uint uVar5;
  uint uVar6;
  size_t __size;
  
  if ((*(char *)(param_4 + 0xc) == '\0') && (*(char *)(param_4 + 0xd) == '\0')) {
    pcVar1 = (char *)(DAT_000136fc + 0x134fc);
  }
  else {
    if (*(int *)(param_5 + 0xcb) != 0) {
      uVar6 = 0;
      pcVar1 = (char *)(DAT_00013708 + 0x136ec);
      __format_00 = (char *)(DAT_0001370c + 0x136f8);
      uVar5 = uVar6;
      do {
        if (*(uint *)(param_5 + 0xbb) <= uVar5) {
          return uVar6;
        }
        iVar4 = *(int *)(param_5 + 0xcb) + uVar5 * 9;
        uVar2 = *(uint *)(iVar4 + 5);
        __offset = *(int *)(iVar4 + 1);
        __format = (char *)(DAT_00013704 + 0x13564);
        for (iVar4 = 0; iVar4 != (uint)((uVar2 & 0xffff) != 0) + (uVar2 >> 0x10); iVar4 = iVar4 + 1)
        {
          __size = uVar2 + iVar4 * -0x10000;
          if (iVar4 == 0 || __size < 0x10000) {
            if (0xffff < uVar2 && iVar4 == 0) {
              __size = 0x10000;
            }
          }
          else {
            __size = 0x10000;
          }
          __ptr = malloc(__size);
          lseek(param_1,__offset,0);
          sigwrap_read(param_1,__ptr,__size);
          lseek(param_2,__offset,0);
          sigwrap_write(param_2,__ptr,__size);
          printf(pcVar1,__offset,__offset,__size);
          __ptr_00 = malloc(__size);
          lseek(param_2,__offset,0);
          sigwrap_read(param_2,__ptr_00,__size);
          for (sVar3 = 0; sVar3 != __size; sVar3 = sVar3 + 1) {
            if (*(char *)((int)__ptr + sVar3) != *(char *)((int)__ptr_00 + sVar3)) {
              uVar6 = 0xffffffff;
              printf(__format_00,(uint)*(byte *)(*(int *)(param_5 + 0xcb) + uVar5 * 9));
              break;
            }
          }
          free(__ptr_00);
          if (uVar6 == 0) {
            printf(__format,(uint)*(byte *)(*(int *)(param_5 + 0xcb) + uVar5 * 9));
          }
          __offset = __offset + 0x10000;
          free(__ptr);
        }
        uVar5 = uVar5 + 1;
      } while( true );
    }
    pcVar1 = (char *)(DAT_00013700 + 0x1351c);
  }
  puts(pcVar1);
  return 0;
}

