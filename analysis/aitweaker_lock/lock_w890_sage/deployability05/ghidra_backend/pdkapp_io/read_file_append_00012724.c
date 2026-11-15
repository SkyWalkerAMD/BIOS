
/* WARNING: Type propagation algorithm not settling */

undefined4 read_file_append(char *param_1,char *param_2,int *param_3,undefined4 *param_4)

{
  int iVar1;
  FILE *__stream;
  FILE *pFVar2;
  FILE *__n;
  char *pcVar3;
  void *pvVar4;
  FILE *pFVar5;
  uint uVar6;
  uint extraout_r3;
  undefined4 uVar7;
  char *__size;
  FILE *__stream_00;
  int *piVar8;
  
  pcVar3 = param_2;
  piVar8 = param_3;
  iVar1 = access(param_1,0);
  if (iVar1 == 0) {
    __stream = fopen(param_1,(char *)(DAT_00012984 + 0x12758));
    if (__stream == (FILE *)0x0) {
      printf((char *)(DAT_00012988 + 0x12774),param_1);
      return 0xffffffff;
    }
    fseek(__stream,0,2);
    pFVar2 = (FILE *)ftell(__stream);
    rewind(__stream);
  }
  else {
    pFVar2 = (FILE *)0x0;
    __stream = pFVar2;
  }
  iVar1 = access(param_2,0);
  uVar6 = (uint)pFVar2 & 0xffffefff;
  if (uVar6 == 0 && iVar1 == 0) {
    __stream_00 = fopen(param_2,(char *)(DAT_0001298c + 0x127d0));
    if (__stream_00 == (FILE *)0x0) {
      uVar7 = 0xffffffff;
      printf((char *)(DAT_00012990 + 0x127ec),param_2);
      goto LAB_000127ec;
    }
    fseek(__stream_00,0,2);
    __n = (FILE *)ftell(__stream_00);
    rewind(__stream_00);
    uVar6 = extraout_r3;
  }
  else {
    __stream_00 = (FILE *)0x0;
    __n = __stream_00;
  }
  __size = (char *)((int)(((FILE *)(((FILE *)(__n->_shortbuf + -0x47))->_shortbuf + -0x47))->
                          _shortbuf + -0x47) +
                   (int)((FILE *)(((FILE *)(((FILE *)(pFVar2->_shortbuf + -0x47))->_shortbuf + -0x47
                                           ))->_shortbuf + -0x47))->_shortbuf + 0xffffffb9U);
  printf((char *)(DAT_00012994 + 0x12844),pFVar2,__n,uVar6,param_4,pcVar3,piVar8);
  uVar6 = (uint)(__size + -0x2001000) & 0xfdffffff;
  if (uVar6 == 0) {
    pvVar4 = malloc((size_t)__size);
    *param_3 = (int)pvVar4;
    if (pvVar4 == (void *)0x0) {
      pcVar3 = (char *)(DAT_0001299c + 0x128a8);
      param_2 = __size;
      goto LAB_00012860;
    }
    iVar1 = access(param_1,uVar6);
    if ((iVar1 == 0) &&
       (pFVar5 = (FILE *)fread((void *)*param_3,1,(size_t)pFVar2,__stream), pFVar5 != pFVar2)) {
      pcVar3 = (char *)(DAT_000129a0 + 0x128e4);
      param_2 = param_1;
      goto LAB_00012860;
    }
    iVar1 = access(param_2,0);
    if (iVar1 == 0) {
      if (pFVar2 == (FILE *)0x1000) {
        pFVar2 = (FILE *)fread((void *)(*param_3 + 0x1000),1,(size_t)__n,__stream_00);
        if (pFVar2 == __n) goto LAB_00012964;
        pcVar3 = (char *)(DAT_000129a4 + 0x12930);
      }
      else {
        if ((pFVar2 != (FILE *)0x0) ||
           (pcVar3 = (char *)fread((void *)*param_3,1,(size_t)__size,__stream_00), pcVar3 == __size)
           ) goto LAB_00012964;
        pcVar3 = (char *)(DAT_000129a8 + 0x12964);
      }
      goto LAB_00012860;
    }
LAB_00012964:
    uVar7 = 0;
    pcVar3 = (char *)(DAT_000129ac + 0x1297c);
    *param_4 = __size;
    printf(pcVar3,__size);
  }
  else {
    pcVar3 = (char *)(DAT_00012998 + 0x12864);
    param_2 = __size;
LAB_00012860:
    uVar7 = 0xffffffff;
    printf(pcVar3,param_2);
  }
  if (__stream_00 != (FILE *)0x0) {
    fclose(__stream_00);
  }
LAB_000127ec:
  if (__stream != (FILE *)0x0) {
    fclose(__stream);
  }
  return uVar7;
}

