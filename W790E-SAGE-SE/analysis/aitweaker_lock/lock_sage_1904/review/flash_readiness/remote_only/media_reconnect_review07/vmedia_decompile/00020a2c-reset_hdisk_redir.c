
undefined4 reset_hdisk_redir(char *param_1,undefined4 *param_2,byte *param_3)

{
  int iVar1;
  char cVar2;
  int iVar3;
  void *__ptr;
  size_t sVar4;
  int iVar5;
  undefined4 uVar6;
  char *__s;
  undefined4 uVar7;
  int iVar8;
  void *__ptr_00;
  void *__ptr_01;
  void *local_34;
  undefined4 local_30;
  int local_2c [2];
  
  local_34 = (void *)0x0;
  local_2c[0] = 0;
  if ((param_1 == (char *)0x0) || (*param_1 == '\0')) goto LAB_00020a54;
  iVar3 = FUN_0001f9ac(&local_30);
  if (iVar3 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00020db8,DAT_00020db4,DAT_00020db0);
    return 1;
  }
  iVar3 = FUN_0001f688(&local_34,local_2c);
  if (iVar3 == 0) {
    if (local_34 == (void *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00020dcc,DAT_00020db4,DAT_00020dc8);
      FUN_0001f664(local_30);
      return 0;
    }
    if (local_2c[0] < 1) {
      free(local_34);
      iVar3 = FUN_0001fa54(0,0);
      uVar7 = DAT_00020dd4;
      uVar6 = DAT_00020dd0;
      if (iVar3 != 0) goto LAB_00020cbc;
      FUN_0001f664(local_30);
    }
    else {
      iVar3 = 0;
      iVar8 = 0;
      __ptr_00 = (void *)0x0;
      __ptr_01 = local_34;
      do {
        while( true ) {
          iVar1 = iVar3 * 0xb4;
          __s = (char *)((int)__ptr_01 + iVar1);
          sVar4 = strlen(__s);
          iVar5 = strncmp(__s,param_1,sVar4 + 1);
          if (iVar5 != 0) break;
          cVar2 = __s[0xaf];
          if (cVar2 == '\0') {
            if (__s[0xae] != '\0') {
LAB_00020ad0:
              *param_2 = 0;
              memset(param_1,0,0x81);
              *param_3 = __s[0xaf] | __s[0xae];
              break;
            }
          }
          else {
            __s[0xaf] = cVar2 + -1;
            if ((__s[0xae] != '\0') || (cVar2 != '\x01')) goto LAB_00020ad0;
          }
          iVar5 = snprintf(param_1,0x80,DAT_00020dac,__s);
          if (iVar5 == 0x80) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00020ddc,DAT_00020db4,DAT_00020dd8);
            if (local_34 != (void *)0x0) {
              free(local_34);
            }
            local_34 = (void *)0x0;
            if (__ptr_00 != (void *)0x0) {
              free(__ptr_00);
            }
            FUN_0001f664(local_30);
            return 0xffffffff;
          }
          iVar3 = iVar3 + 1;
          *param_2 = *(undefined4 *)((int)local_34 + iVar1 + 0xb0);
          *(undefined1 *)((int)local_34 + iVar1 + 0xb0) = 0;
          *(undefined1 *)((int)local_34 + iVar1 + 0xb1) = 0;
          *(undefined1 *)((int)local_34 + iVar1 + 0xb2) = 0;
          *(undefined1 *)((int)local_34 + iVar1 + 0xb3) = 0;
          memset(local_34,0,0x81);
          __ptr = __ptr_00;
          __ptr_01 = local_34;
          if (local_2c[0] <= iVar3) goto LAB_00020c08;
        }
        iVar8 = iVar8 + 1;
        __ptr = realloc(__ptr_00,iVar8 * 0xb4);
        if (__ptr == (void *)0x0) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00020dc0,DAT_00020db4,DAT_00020dbc);
          if (local_34 != (void *)0x0) {
            free(local_34);
          }
          local_34 = (void *)0x0;
          if (__ptr_00 != (void *)0x0) {
            free(__ptr_00);
          }
          FUN_0001f664(local_30);
          return 0xfffffff4;
        }
        memcpy((void *)((int)__ptr + (iVar8 * 0xb4 - 0xb4U)),__s,0xb4);
        iVar3 = iVar3 + 1;
        __ptr_00 = __ptr;
      } while (iVar3 < local_2c[0]);
LAB_00020c08:
      free(__ptr_01);
      iVar3 = FUN_0001fa54(__ptr,iVar8);
      if (iVar3 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00020dd4,DAT_00020db4,DAT_00020dd0);
        FUN_0001f664(local_30);
        if (__ptr != (void *)0x0) {
          free(__ptr);
          return 3;
        }
        goto LAB_00020ccc;
      }
      FUN_0001f664(local_30);
      if (__ptr != (void *)0x0) {
        free(__ptr);
        return 0;
      }
    }
LAB_00020a54:
    uVar7 = 0;
  }
  else {
    uVar7 = DAT_00020dc4;
    uVar6 = 0x2c4;
LAB_00020cbc:
    IDBG_LINUXAPP_DbgOut(0x82,uVar7,DAT_00020db4,uVar6);
    FUN_0001f664(local_30);
LAB_00020ccc:
    uVar7 = 3;
  }
  return uVar7;
}

