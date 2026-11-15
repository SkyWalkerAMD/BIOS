
int PDK_ASUSBIOSConfiguration(int param_1,int param_2,undefined4 param_3,int param_4,int param_5)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  char *__ptr;
  char *__ptr_00;
  Elf32_Ehdr *pEVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  int iVar8;
  Elf32_Ehdr *__size;
  uint uVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  int local_40;
  uint local_2c;
  
  if (*(char *)(param_4 + 0xf) == 'M') {
    *DAT_000132e4 = 1;
  }
  if ((*(char *)(param_4 + 0xc) == '\0') && (*(char *)(param_4 + 0xd) == '\0')) {
    puts(DAT_000132fc);
    return 0;
  }
  iVar8 = *(int *)(param_5 + 0xcb);
  if (iVar8 == 0) {
    puts(DAT_000132f8);
  }
  else {
    uVar9 = (uint)*(byte *)(param_5 + 0xbb);
    uVar11 = (uint)*(byte *)(param_5 + 0xbc);
    uVar12 = (uint)*(byte *)(param_5 + 0xbd);
    uVar3 = (uint)*(byte *)(param_5 + 0xbe);
    if (*(int *)(param_5 + 0xbb) != 0) {
      local_2c = 0;
      local_40 = 0;
      do {
        iVar2 = local_2c * 9;
        __size = *(Elf32_Ehdr **)(iVar8 + iVar2 + 5);
        iVar8 = *(int *)(iVar8 + iVar2 + 1);
        iVar5 = (uint)(((uint)__size & (uint)DAT_000132e8) != 0) + ((uint)__size >> 0x10);
        if (iVar5 != 0) {
          bVar1 = __size <= DAT_000132e8;
          iVar10 = 0;
          do {
            if ((iVar10 == 0 || __size < &Elf32_Ehdr_00010000) && (iVar10 != 0 || bVar1)) {
              __ptr = malloc((size_t)__size);
              lseek(param_1,iVar8,0);
              sigwrap_read(param_1,__ptr,__size);
              lseek(param_2,iVar8,0);
              sigwrap_write(param_2,__ptr,__size);
              printf(DAT_000132ec,iVar8,iVar8,__size);
              __ptr_00 = malloc((size_t)__size);
              lseek(param_2,iVar8,0);
              sigwrap_read(param_2,__ptr_00,__size);
              pEVar4 = __size;
              if (__size != (Elf32_Ehdr *)0x0) goto LAB_000130dc;
LAB_00013118:
              free(__ptr_00);
              if (local_40 == 0) {
                printf(DAT_000132f0,(uint)*(byte *)(*(int *)(param_5 + 0xcb) + iVar2));
              }
              else {
                local_40 = -1;
              }
            }
            else {
              __ptr = malloc(0x10000);
              lseek(param_1,iVar8,0);
              sigwrap_read(param_1,__ptr,0x10000);
              lseek(param_2,iVar8,0);
              sigwrap_write(param_2,__ptr,0x10000);
              printf(DAT_000132ec,iVar8,iVar8,0x10000);
              __ptr_00 = malloc(0x10000);
              lseek(param_2,iVar8,0);
              sigwrap_read(param_2,__ptr_00,0x10000);
              pEVar4 = &Elf32_Ehdr_00010000;
LAB_000130dc:
              if (*__ptr == *__ptr_00) {
                pcVar6 = __ptr_00;
                pcVar7 = __ptr;
                do {
                  if (pEVar4 <= (Elf32_Ehdr *)(pcVar7 + (1 - (int)__ptr))) goto LAB_00013118;
                  pcVar7 = pcVar7 + 1;
                  pcVar6 = pcVar6 + 1;
                } while (*pcVar7 == *pcVar6);
              }
              printf(DAT_000132f4,(uint)*(byte *)(*(int *)(param_5 + 0xcb) + iVar2));
              free(__ptr_00);
              local_40 = -1;
            }
            free(__ptr);
            iVar10 = iVar10 + 1;
            __size = (Elf32_Ehdr *)&__size[-0x4ed].e_flags;
            iVar8 = iVar8 + 0x10000;
          } while (iVar5 != iVar10);
          uVar9 = (uint)*(byte *)(param_5 + 0xbb);
          uVar11 = (uint)*(byte *)(param_5 + 0xbc);
          uVar12 = (uint)*(byte *)(param_5 + 0xbd);
          uVar3 = (uint)*(byte *)(param_5 + 0xbe);
        }
        local_2c = local_2c + 1;
        if ((uVar9 | uVar11 << 8 | uVar12 << 0x10 | uVar3 << 0x18) <= local_2c) {
          return local_40;
        }
        iVar8 = *(int *)(param_5 + 0xcb);
      } while( true );
    }
  }
  return 0;
}

