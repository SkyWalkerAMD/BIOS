
undefined4 * iniparser_loaddef(char *param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *__s2;
  FILE *pFVar4;
  FILE *__stream;
  undefined4 *__ptr;
  void *pvVar5;
  char *pcVar6;
  int iVar7;
  char *pcVar8;
  size_t sVar9;
  FILE *__stream_00;
  char acStack_1038 [1028];
  undefined1 local_c34 [1028];
  undefined1 auStack_830 [1026];
  char acStack_42e [1034];
  
  if (param_1 == (char *)0x0) {
    __stream_00 = (FILE *)0x0;
    if (param_2 == (char *)0x0) {
      return (undefined4 *)0x0;
    }
  }
  else {
    pFVar4 = fopen(param_1,DAT_00012a60);
    __stream_00 = pFVar4;
    if (param_2 == (char *)0x0) {
      __stream = (FILE *)0x0;
      goto LAB_0001274c;
    }
  }
  __stream = fopen(param_2,DAT_00012a60);
  pFVar4 = (FILE *)((uint)__stream | (uint)__stream_00);
LAB_0001274c:
  if (pFVar4 != (FILE *)0x0) {
    __ptr = calloc(1,0xc);
    if (__ptr == (undefined4 *)0x0) {
      if (__stream_00 != (FILE *)0x0) {
        fclose(__stream_00);
      }
      if (__stream != (FILE *)0x0) {
        fclose(__stream);
        return (undefined4 *)0x0;
      }
    }
    else {
      pvVar5 = calloc(0x2000,4);
      *__ptr = pvVar5;
      __s2 = DAT_00012a6c;
      uVar3 = DAT_00012a68;
      uVar2 = DAT_00012a64;
      if (pvVar5 != (void *)0x0) {
        __ptr[1] = 0;
        __ptr[2] = 0;
        local_c34[0] = 0;
        do {
          if ((__stream_00 == (FILE *)0x0) ||
             (pcVar6 = fgets(acStack_1038,0x400,__stream_00), pcVar6 == (char *)0x0)) {
            if (__stream == (FILE *)0x0) goto LAB_000128e4;
            pcVar6 = fgets(acStack_1038,0x400,__stream);
            if (pcVar6 == (char *)0x0) {
              fclose(__stream);
LAB_000128e4:
              if (__stream_00 == (FILE *)0x0) {
                return __ptr;
              }
              fclose(__stream_00);
              return __ptr;
            }
          }
          pcVar6 = (char *)strskp(acStack_1038);
          cVar1 = *pcVar6;
          if (cVar1 != '\0' && (cVar1 != '#' && cVar1 != ';')) {
            iVar7 = __isoc99_sscanf(pcVar6,uVar2,local_c34);
            if (iVar7 == 1) {
              iniparser_add_entry(__ptr,local_c34,0,0);
            }
            else {
              pcVar8 = strchr(pcVar6,0x3d);
              if ((pcVar8 != (char *)0x0) &&
                 (iVar7 = __isoc99_sscanf(pcVar6,uVar3,auStack_830,acStack_42e + 2), iVar7 == 2)) {
                sVar9 = strlen(acStack_42e + 2);
                if (acStack_42e[2] == '\"') {
                  if ((acStack_42e[(sVar9 & 0xff) + 1] == '\"') ||
                     (acStack_42e[sVar9 & 0xff] == '\"')) goto LAB_00012964;
                }
                else if ((acStack_42e[2] == '\'') &&
                        ((acStack_42e[(sVar9 & 0xff) + 1] == '\'' ||
                         (acStack_42e[sVar9 & 0xff] == '\'')))) {
LAB_00012964:
                  iVar7 = __isoc99_sscanf(pcVar6,DAT_00012a74,auStack_830,acStack_42e + 2);
                  if (iVar7 != 2) {
                    __isoc99_sscanf(pcVar6,DAT_00012a78,auStack_830,acStack_42e + 2);
                  }
                }
                iVar7 = strcmp(acStack_42e + 2,__s2);
                if ((iVar7 == 0) || (iVar7 = strcmp(acStack_42e + 2,DAT_00012a70), iVar7 == 0)) {
                  acStack_42e[2] = '\0';
                }
                else {
                  pcVar6 = (char *)strcrop(acStack_42e + 2);
                  sVar9 = strlen(pcVar6);
                  if (DAT_00012a7c < sVar9 + 1) {
                    printf(DAT_00012a80);
                  }
                  strcrop(acStack_42e + 2);
                }
                iniparser_add_entry(__ptr,local_c34,auStack_830,acStack_42e + 2);
              }
            }
          }
        } while( true );
      }
      if (__stream_00 != (FILE *)0x0) {
        fclose(__stream_00);
      }
      if (__stream != (FILE *)0x0) {
        fclose(__stream);
      }
      free(__ptr);
    }
  }
  return (undefined4 *)0x0;
}

