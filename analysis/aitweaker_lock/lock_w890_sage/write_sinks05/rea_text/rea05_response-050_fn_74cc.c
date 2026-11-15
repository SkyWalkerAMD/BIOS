
undefined8 FUN_000074cc(longlong param_1,longlong param_2)

{
  short *psVar1;
  char *pcVar2;
  ulonglong uVar3;
  longlong lVar4;
  
  uVar3 = 0;
  if ((*(char *)(param_1 + 5) != '\0') || (*(char *)(param_2 + 5) == '\0')) {
    pcVar2 = (char *)(param_2 + 6);
    lVar4 = param_1 - param_2;
    do {
      if ((pcVar2[lVar4] == '\0') && (*pcVar2 != '\0')) {
        return 1;
      }
      if ((pcVar2[lVar4 + 0x3b] == '\0') && (pcVar2[0x3b] != '\0')) {
        return 1;
      }
      pcVar2 = pcVar2 + 1;
    } while (pcVar2 + (-6 - param_2) < &IMAGE_DOS_HEADER_00000000.e_cparhdr);
    if ((((((((*(char *)(param_1 + 0xc5) != '\0') || (*(char *)(param_2 + 0xc5) == '\0')) &&
            ((*(short *)(param_1 + 0xc6) != 0 || (*(short *)(param_2 + 0xc6) == 0)))) &&
           (((*(short *)(param_1 + 200) != 0 || (*(short *)(param_2 + 200) == 0)) &&
            ((*(short *)(param_1 + 0xcb) != 0 || (*(short *)(param_2 + 0xcb) == 0)))))) &&
          ((((*(char *)(param_1 + 0x269) != '\0' || (*(char *)(param_2 + 0x269) == '\0')) &&
            ((*(short *)(param_1 + 0x26a) != 0 || (*(short *)(param_2 + 0x26a) == 0)))) &&
           ((*(short *)(param_1 + 0x26c) != 0 || (*(short *)(param_2 + 0x26c) == 0)))))) &&
         ((*(short *)(param_1 + 0x26f) != 0 || (*(short *)(param_2 + 0x26f) == 0)))) &&
        (((((*(char *)(param_1 + 0x24d) != '\0' || (*(char *)(param_2 + 0x24d) == '\0')) &&
           ((*(short *)(param_1 + 0x24e) != 0 || (*(short *)(param_2 + 0x24e) == 0)))) &&
          (((*(short *)(param_1 + 0x250) != 0 || (*(short *)(param_2 + 0x250) == 0)) &&
           ((*(short *)(param_1 + 0x253) != 0 || (*(short *)(param_2 + 0x253) == 0)))))) &&
         ((((*(char *)(param_1 + 0x3f1) != '\0' || (*(char *)(param_2 + 0x3f1) == '\0')) &&
           ((*(short *)(param_1 + 0x3f2) != 0 || (*(short *)(param_2 + 0x3f2) == 0)))) &&
          ((*(short *)(param_1 + 0x3f4) != 0 || (*(short *)(param_2 + 0x3f4) == 0)))))))) &&
       ((*(short *)(param_1 + 0x3f7) != 0 || (*(short *)(param_2 + 0x3f7) == 0)))) {
      pcVar2 = (char *)(param_2 + 0xe);
      psVar1 = (short *)(param_2 + 0xfd);
      do {
        if ((pcVar2[lVar4] == '\0') && (*pcVar2 != '\0')) {
          return 1;
        }
        if ((pcVar2[lVar4 + 0x3b] == '\0') && (pcVar2[0x3b] != '\0')) {
          return 1;
        }
        if ((pcVar2[lVar4 + 0xbf] == '\0') && (pcVar2[0xbf] != '\0')) {
          return 1;
        }
        if ((*(short *)((longlong)psVar1 + lVar4) == 0) && (*psVar1 != 0)) {
          return 1;
        }
        if ((*(short *)(lVar4 + 0x60 + (longlong)psVar1) == 0) && (psVar1[0x30] != 0)) {
          return 1;
        }
        if ((*(short *)(lVar4 + 0xf0 + (longlong)psVar1) == 0) && (psVar1[0x78] != 0)) {
          return 1;
        }
        if ((pcVar2[lVar4 + 0x263] == '\0') && (pcVar2[0x263] != '\0')) {
          return 1;
        }
        if ((*(short *)(lVar4 + 0x1a4 + (longlong)psVar1) == 0) && (psVar1[0xd2] != 0)) {
          return 1;
        }
        if ((*(short *)(lVar4 + 0x204 + (longlong)psVar1) == 0) && (psVar1[0x102] != 0)) {
          return 1;
        }
        if ((*(short *)(lVar4 + 0x294 + (longlong)psVar1) == 0) && (psVar1[0x14a] != 0)) {
          return 1;
        }
        pcVar2 = pcVar2 + 1;
        psVar1 = psVar1 + 1;
      } while (pcVar2 + (-0xe - param_2) <
               (char *)((longlong)IMAGE_DOS_HEADER_00000000.e_res2_10_ + 7));
      if (((((((*(short *)(param_1 + 0x40f) != 0) || (*(short *)(param_2 + 0x40f) == 0)) &&
             ((*(short *)(param_1 + 0x411) != 0 || (*(short *)(param_2 + 0x411) == 0)))) &&
            ((*(short *)(param_1 + 0x415) != 0 || (*(short *)(param_2 + 0x415) == 0)))) &&
           ((*(short *)(param_1 + 0x417) != 0 || (*(short *)(param_2 + 0x417) == 0)))) &&
          (((*(short *)(param_1 + 0x419) != 0 || (*(short *)(param_2 + 0x419) == 0)) &&
           ((*(short *)(param_1 + 0x41b) != 0 || (*(short *)(param_2 + 0x41b) == 0)))))) &&
         (((*(short *)(param_1 + 0x41d) != 0 || (*(short *)(param_2 + 0x41d) == 0)) &&
          ((*(short *)(param_1 + 0x41f) != 0 || (*(short *)(param_2 + 0x41f) == 0)))))) {
        psVar1 = (short *)(param_2 + 0x255);
        do {
          if ((*(short *)((longlong)psVar1 + lVar4) == 0) && (*psVar1 != 0)) {
            return 1;
          }
          if ((*(short *)((longlong)psVar1 + lVar4 + 0x1a4) == 0) && (psVar1[0xd2] != 0)) {
            return 1;
          }
          uVar3 = uVar3 + 1;
          psVar1 = psVar1 + 1;
        } while (uVar3 < 10);
        if (((*(char *)(param_1 + 4) == *(char *)(param_2 + 4)) ||
            (*(char *)(param_2 + 4) != '\x01')) &&
           ((*(char *)(param_1 + 0x421) == *(char *)(param_2 + 0x421) ||
            (*(char *)(param_2 + 0x421) != '\x01')))) {
          return 0;
        }
      }
    }
  }
  return 1;
}

