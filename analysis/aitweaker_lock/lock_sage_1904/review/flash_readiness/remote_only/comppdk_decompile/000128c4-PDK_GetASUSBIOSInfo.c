
undefined4 PDK_GetASUSBIOSInfo(int param_1,uint param_2,void *param_3,__off_t param_4)

{
  char cVar1;
  bool bVar2;
  char *pcVar3;
  void *__ptr;
  char *__s1;
  int iVar4;
  void *pvVar5;
  uint uVar6;
  uint uVar7;
  char *pcVar8;
  char *pcVar9;
  int iVar10;
  uint local_50;
  uint local_4c;
  undefined4 local_34;
  undefined4 local_30;
  undefined2 local_2c;
  
  param_2 = param_2 >> 0xb;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  __ptr = malloc(0x800);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00012ed4,DAT_00012ed0,param_4);
  lseek(param_1,param_4,0);
  pcVar9 = DAT_00012edc;
  pcVar3 = DAT_00012ed8;
  if (param_2 != 0) {
    local_4c = 0;
    uVar7 = param_4;
    do {
      local_50 = uVar7 + 0x800;
      pcVar8 = (char *)0x0;
      sigwrap_read(param_1,__ptr,0x800);
      iVar10 = uVar7 + -1;
      uVar6 = local_4c + 1;
      while( true ) {
        __s1 = memchr((char *)((int)__ptr + (int)pcVar8),0x24,0x800 - (int)pcVar8);
        if (__s1 == (char *)0x0) break;
        pcVar8 = __s1 + (1 - (int)__ptr);
        if (pcVar3 < __s1 + (10 - (int)__ptr)) {
          lseek(param_1,(__off_t)(pcVar8 + iVar10),0);
          local_34 = 0;
          local_30 = 0;
          local_2c = 0;
          sigwrap_read(param_1,&local_34,9);
          iVar4 = strncmp((char *)&local_34,pcVar9,9);
          if (iVar4 == 0) {
            printf(DAT_00012f08,pcVar8 + iVar10,local_4c,pcVar8);
            goto LAB_000129d0;
          }
          lseek(param_1,local_50,0);
        }
        else {
          iVar4 = strncmp(__s1,pcVar9,9);
          if (iVar4 == 0) {
            printf(DAT_00012ee0,pcVar8 + iVar10,local_4c,pcVar8);
LAB_000129d0:
            lseek(param_1,(__off_t)(pcVar8 + iVar10),0);
            sigwrap_read(param_1,__ptr,0x800);
            memcpy(param_3,__ptr,0xcb);
            if (*(int *)((int)param_3 + 0xbf) == 0) {
              if (*(int *)((int)param_3 + 0xbb) == 0) {
                *(undefined1 *)((int)param_3 + 0xcb) = 0;
                *(undefined1 *)((int)param_3 + 0xcc) = 0;
                *(undefined1 *)((int)param_3 + 0xcd) = 0;
                *(undefined1 *)((int)param_3 + 0xce) = 0;
                goto LAB_00012a50;
              }
              pvVar5 = calloc(*(int *)((int)param_3 + 0xbb) * 9,1);
              *(char *)((int)param_3 + 0xcd) = (char)((uint)pvVar5 >> 0x10);
              cVar1 = *(char *)((int)param_3 + 0xf);
              *(char *)((int)param_3 + 0xcb) = (char)pvVar5;
              *(char *)((int)param_3 + 0xcc) = (char)((uint)pvVar5 >> 8);
              *(char *)((int)param_3 + 0xce) = (char)((uint)pvVar5 >> 0x18);
            }
            else {
              printf(DAT_00012f00,*(undefined4 *)((int)param_3 + 0x75));
              if (*(int *)((int)param_3 + 0x75) == 0x1000000) {
                param_4 = CONCAT13(*(undefined1 *)((int)param_3 + 0xc2),
                                   CONCAT12(*(undefined1 *)((int)param_3 + 0xc1),
                                            CONCAT11(*(undefined1 *)((int)param_3 + 0xc0),
                                                     *(undefined1 *)((int)param_3 + 0xbf)))) +
                          0x1000000 + param_4;
              }
              else {
                param_4 = CONCAT13(*(undefined1 *)((int)param_3 + 0xc2),
                                   CONCAT12(*(undefined1 *)((int)param_3 + 0xc1),
                                            CONCAT11(*(undefined1 *)((int)param_3 + 0xc0),
                                                     *(undefined1 *)((int)param_3 + 0xbf)))) +
                          *(int *)((int)param_3 + 0x75);
              }
              pvVar5 = malloc(*(int *)((int)param_3 + 0xbb) * 9);
              *(char *)((int)param_3 + 0xcb) = (char)pvVar5;
              *(char *)((int)param_3 + 0xcd) = (char)((uint)pvVar5 >> 0x10);
              *(char *)((int)param_3 + 0xcc) = (char)((uint)pvVar5 >> 8);
              *(char *)((int)param_3 + 0xce) = (char)((uint)pvVar5 >> 0x18);
              printf(DAT_00012f04,param_4);
              lseek(param_1,param_4,0);
              sigwrap_read(param_1,__ptr,0x800);
              memcpy(*(void **)((int)param_3 + 0xcb),__ptr,*(int *)((int)param_3 + 0xbb) * 9);
LAB_00012a50:
              cVar1 = *(char *)((int)param_3 + 0xf);
            }
            if (cVar1 == 'M') {
              *DAT_00012ee4 = 1;
              goto LAB_00012b74;
            }
            if (*DAT_00012ee4 != 0) goto LAB_00012b74;
            lseek(param_1,0,0);
            pcVar3 = DAT_00012ee8;
            local_50 = 0;
            goto LAB_00012a80;
          }
        }
      }
      local_4c = uVar6;
      uVar7 = local_50;
    } while (uVar6 != param_2);
  }
  puts(DAT_00012ef4);
  if (__ptr != (void *)0x0) {
    free(__ptr);
  }
  return 0xffffffff;
LAB_00012a80:
  pcVar9 = (char *)0x0;
  bVar2 = false;
  sigwrap_read(param_1,__ptr,0x800);
  uVar7 = local_50 + 1;
  iVar10 = uVar7 * 0x800 + -0x801;
  while( true ) {
    pcVar8 = memchr((char *)((int)__ptr + (int)pcVar9),0x24,0x800 - (int)pcVar9);
    if (pcVar8 == (char *)0x0) break;
    pcVar9 = pcVar8 + (1 - (int)__ptr);
    if (pcVar8 + (5 - (int)__ptr) < (char *)0x800) {
      iVar4 = strncmp(pcVar8,pcVar3,4);
      if (iVar4 == 0) {
        lseek(param_1,(__off_t)(pcVar9 + iVar10),0);
        sigwrap_read(param_1,__ptr,0x800);
        memcpy((void *)((int)param_3 + 0xcf),(void *)((int)__ptr + 8),8);
        printf(DAT_00012eec,pcVar9 + iVar10,local_50);
        printf(DAT_00012ef0,(uint)*(ushort *)((int)param_3 + 0xcf),
               (uint)*(ushort *)((int)param_3 + 0xd1),(uint)*(ushort *)((int)param_3 + 0xd3),
               (uint)*(ushort *)((int)param_3 + 0xd5));
        goto LAB_00012b74;
      }
    }
    else {
      pcVar8 = pcVar9 + iVar10;
      lseek(param_1,(__off_t)pcVar8,0);
      local_34 = 0;
      local_30 = 0;
      local_2c = 0;
      sigwrap_read(param_1,&local_34,4);
      iVar4 = strncmp((char *)&local_34,pcVar3,4);
      if (iVar4 != 0) {
        lseek(param_1,uVar7 * 0x800,0);
        break;
      }
      lseek(param_1,(__off_t)pcVar8,0);
      sigwrap_read(param_1,__ptr,0x800);
      memcpy((void *)((int)param_3 + 0xcf),(void *)((int)__ptr + 8),8);
      printf(DAT_00012ef8,pcVar8,local_50);
      printf(DAT_00012efc,(uint)*(ushort *)((int)param_3 + 0xcf),
             (uint)*(ushort *)((int)param_3 + 0xd1),(uint)*(ushort *)((int)param_3 + 0xd3),
             (uint)*(ushort *)((int)param_3 + 0xd5));
      bVar2 = true;
    }
  }
  if ((bVar2) || (local_50 = uVar7, uVar7 == param_2)) {
LAB_00012b74:
    free(__ptr);
    return 0;
  }
  goto LAB_00012a80;
}

