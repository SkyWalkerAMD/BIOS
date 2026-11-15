
void PDK_GetASUSBIOSInfo(int param_1,undefined4 param_2,void *param_3,uint param_4)

{
  bool bVar1;
  void *__s;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  int iVar6;
  void *pvVar7;
  char *pcVar8;
  uint uVar9;
  int iVar10;
  char *pcVar11;
  char *pcVar12;
  size_t sVar13;
  int *piVar14;
  uint uVar15;
  __off_t __offset;
  int iVar16;
  uint local_d0;
  undefined1 auStack_c0 [8];
  uint local_b8;
  undefined1 auStack_a0 [16];
  uint local_90;
  int local_48;
  int local_44;
  undefined2 local_40;
  int local_3c;
  
  iVar10 = DAT_0001344c + 0x12df4;
  local_3c = **(int **)(DAT_00013450 + 0x12e00 + DAT_00013454);
  local_48 = 0;
  local_44 = 0;
  local_40 = 0;
  __s = malloc(0x800);
  if (__s == (void *)0x0) {
    puts((char *)(DAT_00013458 + 0x12e3c));
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013464 + 0x12e88,DAT_00013460 + 0x12e97,param_4);
    iVar3 = FUN_00014234(param_1,auStack_a0);
    if (iVar3 < 0) {
      pcVar4 = (char *)(DAT_00013468 + 0x12ea8);
LAB_00012ea4:
      perror(pcVar4);
    }
    else {
      if ((local_90 & 0xf000) != 0x2000) {
        uVar9 = lseek(param_1,0,2);
        if (-1 < (int)uVar9) {
          local_b8 = uVar9;
          lseek(param_1,0,0);
          goto LAB_00012f1c;
        }
        pcVar4 = (char *)(DAT_00013474 + 0x12f08);
        goto LAB_00012ea4;
      }
      iVar3 = ioctl(param_1,DAT_0001346c,auStack_c0);
      if (iVar3 < 0) {
        pcVar4 = (char *)(DAT_00013470 + 0x12ee8);
        goto LAB_00012ea4;
      }
LAB_00012f1c:
      if (param_4 < local_b8) {
        if ((param_4 & 0x7ff) != 0) {
          uVar9 = 0x800;
          pcVar4 = (char *)(DAT_0001347c + 0x12f5c);
          goto LAB_00012f34;
        }
        local_d0 = local_b8 - param_4 >> 0xb;
        if ((local_b8 - param_4 & 0x7ff) == 0) {
          if (local_d0 != 0) goto LAB_00012f88;
          pcVar4 = (char *)(DAT_00013490 + 0x1304c);
        }
        else {
          local_d0 = local_d0 + 1;
LAB_00012f88:
          iVar3 = param_4 + (local_d0 - 1) * 0x800;
          pcVar4 = (char *)(DAT_00013480 + 0x12fa4);
          uVar9 = local_d0;
          do {
            uVar9 = uVar9 - 1;
            lseek(param_1,iVar3,0);
            sigwrap_read(param_1,__s,0x800);
            sVar13 = 0x800;
            pcVar11 = (char *)(DAT_00013484 + 0x12fd8);
            pcVar12 = (char *)(DAT_00013488 + 0x12fe4);
LAB_00012fe4:
            do {
              pcVar5 = memrchr(__s,0x24,sVar13);
              if (pcVar5 == (char *)0x0) break;
              sVar13 = (int)pcVar5 - (int)__s;
              iVar16 = sVar13 + iVar3;
              if (iVar16 + 9U <= local_b8) {
                if (sVar13 + 9 < 0x801) {
                  iVar6 = strncmp(pcVar5,pcVar11,9);
                  if (iVar6 != 0) goto LAB_00013020;
                  pcVar4 = (char *)(DAT_00013494 + 0x13088);
                }
                else {
                  lseek(param_1,iVar16,0);
                  local_48 = 0;
                  local_44 = 0;
                  local_40 = 0;
                  sigwrap_read(param_1,&local_48,9);
                  iVar6 = strncmp((char *)&local_48,pcVar4,9);
                  if (iVar6 != 0) goto LAB_00012fe4;
                  pcVar4 = (char *)(DAT_000134c0 + 0x132f0);
                }
                printf(pcVar4,iVar16,uVar9,sVar13);
                lseek(param_1,iVar16,0);
                sigwrap_read(param_1,__s,0x800);
                memcpy(param_3,__s,0xcb);
                piVar14 = *(int **)(iVar10 + DAT_00013498);
                if (*(int *)((int)param_3 + 0xbf) == 0) {
                  if (*(int *)((int)param_3 + 0xbb) == 0) {
                    *(undefined1 *)((int)param_3 + 0xcb) = 0;
                    *(undefined1 *)((int)param_3 + 0xcc) = 0;
                    *(undefined1 *)((int)param_3 + 0xcd) = 0;
                    *(undefined1 *)((int)param_3 + 0xce) = 0;
                  }
                  else {
                    sVar13 = *(int *)((int)param_3 + 0xbb) * 9;
                    pvVar7 = malloc(sVar13);
                    *(void **)((int)param_3 + 0xcb) = pvVar7;
                    memset(pvVar7,0,sVar13);
                  }
                }
                else {
                  printf((char *)(DAT_0001349c + 0x130e0),*(undefined4 *)((int)param_3 + 0x75));
                  if (*piVar14 == 1) {
                    puts((char *)(DAT_000134a0 + 0x130f8));
                    __offset = *(__off_t *)((int)param_3 + 0xbf);
                  }
                  else if (*(int *)((int)param_3 + 0x75) == 0x1000000) {
                    __offset = *(int *)((int)param_3 + 0xbf) + 0x1000000 + param_4;
                  }
                  else {
                    __offset = *(int *)((int)param_3 + 0x75) + *(int *)((int)param_3 + 0xbf);
                  }
                  pvVar7 = malloc(*(int *)((int)param_3 + 0xbb) * 9);
                  *(void **)((int)param_3 + 0xcb) = pvVar7;
                  printf((char *)(DAT_000134a4 + 0x1311c),__offset);
                  lseek(param_1,__offset,0);
                  sigwrap_read(param_1,__s,0x800);
                  memcpy(*(void **)((int)param_3 + 0xcb),__s,*(int *)((int)param_3 + 0xbb) * 9);
                }
                iVar10 = *piVar14;
                if (iVar10 != 0) goto LAB_00013274;
                lseek(param_1,0,0);
                pcVar4 = (char *)(DAT_000134a8 + 0x1317c);
                uVar9 = 0;
                goto LAB_0001317c;
              }
              printf(pcVar12,iVar16);
LAB_00013020:
            } while (sVar13 != 0);
            iVar3 = iVar3 + -0x800;
          } while (uVar9 != 0);
          pcVar4 = (char *)(DAT_0001348c + 0x13040);
        }
        puts(pcVar4);
      }
      else {
        pcVar4 = (char *)(DAT_00013478 + 0x12f38);
        uVar9 = local_b8;
LAB_00012f34:
        printf(pcVar4,param_4,uVar9);
      }
    }
    free(__s);
  }
  uVar2 = 0xffffffff;
LAB_00012e40:
  if (local_3c != **(int **)(DAT_0001345c + 0x12e50 + DAT_00013454)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar2);
  }
  return;
LAB_0001317c:
  do {
    uVar15 = uVar9 + 1;
    pcVar5 = (char *)0x0;
    sigwrap_read(param_1,__s,0x800);
    iVar3 = uVar15 * 0x800 + -0x801;
    bVar1 = false;
    pcVar11 = (char *)(DAT_000134ac + 0x131bc);
    pcVar12 = (char *)(DAT_000134b0 + 0x131c8);
    while (pcVar8 = memchr((char *)((int)__s + (int)pcVar5),0x24,0x800 - (int)pcVar5),
          pcVar8 != (char *)0x0) {
      pcVar5 = pcVar8 + (1 - (int)__s);
      if (pcVar8 + (5 - (int)__s) < (char *)0x800) {
        iVar16 = strncmp(pcVar8,(char *)(DAT_000134b4 + 0x13204),4);
        if (iVar16 == 0) {
          lseek(param_1,(__off_t)(pcVar5 + iVar3),0);
          sigwrap_read(param_1,__s,0x800);
          uVar2 = *(undefined4 *)((int)__s + 0xc);
          *(undefined4 *)((int)param_3 + 0xcf) = *(undefined4 *)((int)__s + 8);
          iVar10 = DAT_000134b8;
          *(undefined4 *)((int)param_3 + 0xd3) = uVar2;
          printf((char *)(iVar10 + 0x13254),pcVar5 + iVar3,uVar9,(int)__s + 0x10);
          printf((char *)(DAT_000134bc + 0x13268),(uint)*(ushort *)((int)param_3 + 0xcf),
                 (uint)*(ushort *)((int)param_3 + 0xd1),(uint)*(ushort *)((int)param_3 + 0xd3),
                 (uint)*(ushort *)((int)param_3 + 0xd5));
          goto LAB_00013274;
        }
      }
      else {
        pcVar8 = pcVar5 + iVar3;
        lseek(param_1,(__off_t)pcVar8,0);
        local_40 = 0;
        local_48 = iVar10;
        local_44 = iVar10;
        sigwrap_read(param_1,&local_48,4);
        iVar16 = strncmp((char *)&local_48,pcVar4,4);
        if (iVar16 != 0) {
          lseek(param_1,uVar15 * 0x800,0);
          break;
        }
        lseek(param_1,(__off_t)pcVar8,0);
        sigwrap_read(param_1,__s,0x800);
        uVar2 = *(undefined4 *)((int)__s + 0xc);
        *(undefined4 *)((int)param_3 + 0xcf) = *(undefined4 *)((int)__s + 8);
        *(undefined4 *)((int)param_3 + 0xd3) = uVar2;
        printf(pcVar11,pcVar8,uVar9);
        printf(pcVar12,(uint)*(ushort *)((int)param_3 + 0xcf),(uint)*(ushort *)((int)param_3 + 0xd1)
               ,(uint)*(ushort *)((int)param_3 + 0xd3),(uint)*(ushort *)((int)param_3 + 0xd5));
        bVar1 = true;
      }
    }
  } while ((!bVar1) && (uVar9 = uVar15, uVar15 < local_d0));
LAB_00013274:
  free(__s);
  uVar2 = 0;
  goto LAB_00012e40;
}

