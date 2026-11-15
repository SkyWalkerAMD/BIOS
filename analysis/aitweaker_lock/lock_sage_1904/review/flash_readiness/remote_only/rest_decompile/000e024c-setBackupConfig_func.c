
void setBackupConfig_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t __n;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  int iVar11;
  int *piVar12;
  uint uVar13;
  bool bVar14;
  bool bVar15;
  int local_14c;
  int local_148;
  int local_144;
  int local_140;
  int local_13c;
  undefined1 auStack_12c [44];
  stat sStack_100;
  char acStack_a8 [132];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_000e0d20);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000e0d30);
    FCGI_printf(DAT_000e0d34);
    qcgires_setcontenttype(iVar2,DAT_000e0d38);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_000e0d3c,uVar8);
    uVar8 = json_object_new_string(DAT_000e0d40);
    json_object_object_add(uVar9,DAT_000e0d44,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_000e0d48,uVar8);
    json_object_put(uVar9);
    goto LAB_000e03c4;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e0d24);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e0d28,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e0d28,0);
    __n = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e0d2c), iVar5 != 0))
    goto LAB_000e0314;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_000e0d50);
    pcVar6 = getenv(DAT_000e0d54);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_000e0d58),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    if (*DAT_000e0d5c == 0) {
LAB_000e04bc:
      memset(acStack_a8,0,0x80);
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d68);
      if (iVar11 == 0) {
        bVar14 = true;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d68);
        iVar11 = json_object_get_int64();
        bVar14 = iVar11 != 0;
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d6c);
      if (iVar11 == 0) {
        bVar15 = true;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d6c);
        iVar11 = json_object_get_int64();
        bVar15 = iVar11 != 0;
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d70);
      if (iVar11 == 0) {
        local_14c = -1;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d70);
        local_14c = json_object_get_int64();
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d74);
      if (iVar11 == 0) {
        local_148 = -1;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d74);
        local_148 = json_object_get_int64();
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d78);
      if (iVar11 == 0) {
        local_144 = -1;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d78);
        local_144 = json_object_get_int64();
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d7c);
      if (iVar11 == 0) {
        local_140 = -1;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d7c);
        local_140 = json_object_get_int64();
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d80);
      if (iVar11 == 0) {
        local_13c = -1;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d80);
        local_13c = json_object_get_int64();
      }
      iVar11 = json_object_object_get_rest(iVar10,DAT_000e0d84);
      if (iVar11 == 0) {
        iVar11 = -1;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_000e0d84);
        iVar11 = json_object_get_int64();
      }
      if (*(int *)(DAT_000e0d88 + 100) != 1) {
        bVar14 = false;
      }
      uVar13 = 0;
      if (bVar14) {
        uVar13 = 0x40;
      }
      if (*(int *)(DAT_000e0d88 + 0x3f8) == 0) {
        bVar15 = false;
      }
      if (bVar15) {
        uVar13 = uVar13 | 0x10;
      }
      if (local_14c != 0) {
        uVar13 = uVar13 | 2;
      }
      if (local_148 != 0) {
        uVar13 = uVar13 | 4;
      }
      if (local_144 != 0) {
        uVar13 = uVar13 | 8;
      }
      if (local_140 != 0) {
        uVar13 = uVar13 | 1;
      }
      if (local_13c != 0) {
        uVar13 = uVar13 | 0x20;
      }
      if (iVar11 != 0) {
        uVar13 = uVar13 | 0x80;
      }
      iVar11 = LIBIPMI_HL_AMISetBackupFlag(auStack_12c,uVar13,0x1e);
      if (iVar11 != 0) {
        IPMI_lo_Logout(auStack_12c);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar10 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000e0ddc,0x25);
          json_object_object_add(iVar10,DAT_000e0d44,uVar9);
          uVar9 = DAT_000e0de0;
LAB_000e0c1c:
          uVar9 = json_object_new_int(uVar9);
          json_object_object_add(iVar10,DAT_000e0db0,uVar9);
          uVar9 = DAT_000e0db4;
          goto LAB_000e0c34;
        }
        strcasecmp(pcVar3,DAT_000e0d58);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e0ddc,0x25);
        json_object_object_add(iVar5,DAT_000e0d44,uVar9);
        uVar9 = DAT_000e0de0;
LAB_000e0834:
        uVar9 = json_object_new_int(uVar9);
        json_object_object_add(iVar5,DAT_000e0db0,uVar9);
        uVar9 = DAT_000e0db4;
LAB_000e084c:
        FCGI_printf(DAT_000e0db8,uVar9);
        qcgires_setcontenttype(iVar2,DAT_000e0d38);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e0d48,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_000e0d58);
        goto LAB_000e099c;
      }
      if (*(int *)(DAT_000e0d88 + 0x318) == 1) {
        snprintf(acStack_a8,0x80,DAT_000e0dd0,DAT_000e0dd4,*(undefined4 *)(DAT_000e0dcc + 0xb4),
                 DAT_000e0d90,DAT_000e0d8c);
      }
      else {
        snprintf(acStack_a8,0x80,DAT_000e0d94,DAT_000e0d98,DAT_000e0d90,DAT_000e0d8c);
      }
      memset(&sStack_100,0,0x58);
      iVar11 = __xstat(3,acStack_a8,&sStack_100);
      if ((iVar11 == 0) && (iVar11 = unlink(acStack_a8), iVar11 != 0)) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000e0dd8,DAT_000e0da0,0x80);
      }
      iVar11 = LIBIPMI_HL_AMIManageBMCConfig_BackupConf(auStack_12c,0x1e);
      pcVar6 = DAT_000e0d9c;
      if (iVar11 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000e0dc0,DAT_000e0da0,0x85,iVar11);
        IPMI_lo_Logout(auStack_12c);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar10 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000e0dc4,0x27);
          json_object_object_add(iVar10,DAT_000e0d44,uVar9);
          uVar9 = DAT_000e0dc8;
          goto LAB_000e0c1c;
        }
        strcasecmp(pcVar3,DAT_000e0d58);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e0dc4,0x27);
        json_object_object_add(iVar5,DAT_000e0d44,uVar9);
        uVar9 = DAT_000e0dc8;
        goto LAB_000e0834;
      }
      memset(&sStack_100,0,0x58);
      iVar11 = __lxstat(3,pcVar6,&sStack_100);
      if ((iVar11 == 0) && (iVar11 = unlink(pcVar6), iVar11 < 0)) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_000e0dbc,DAT_000e0da0,0x8c,pcVar6);
      }
      iVar11 = symlink(acStack_a8,DAT_000e0d9c);
      if (iVar11 != 0) {
        piVar12 = __errno_location();
        pcVar6 = strerror(*piVar12);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000e0da4,DAT_000e0da0,0x90,pcVar6);
        IPMI_lo_Logout(auStack_12c);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar10 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000e0da8,0x14);
          json_object_object_add(iVar10,DAT_000e0d44,uVar9);
          uVar9 = DAT_000e0dac;
          goto LAB_000e0c1c;
        }
        strcasecmp(pcVar3,DAT_000e0d58);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e0da8,0x14);
        json_object_object_add(iVar5,DAT_000e0d44,uVar9);
        uVar9 = DAT_000e0dac;
        goto LAB_000e0834;
      }
      pcVar6 = getenv(DAT_000e0d50);
      pcVar7 = getenv(DAT_000e0d54);
      if (((pcVar6 != (char *)0x0 && pcVar7 != (char *)0x0) &&
          (iVar11 = strcasecmp(pcVar6,DAT_000e0d58), iVar11 != 0)) &&
         (iVar11 = strncasecmp(pcVar7,DAT_000e0d38,0x10), iVar11 == 0)) {
        qcgires_setcontenttype(iVar2,DAT_000e0d38);
        uVar9 = json_object_to_json_string(iVar10);
        FCGI_printf(DAT_000e0d48,uVar9);
      }
      IPMI_lo_Logout(auStack_12c);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000e0d58);
        goto LAB_000e099c;
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e0d60);
      iVar11 = IPMI_lo_Login(DAT_000e0d64,DAT_000e0d64,auStack_12c,uVar1,1,0,0,0);
      if (iVar11 == 0) goto LAB_000e04bc;
      IPMI_lo_Logout(auStack_12c);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000e0d58);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e0de4,0x20);
        json_object_object_add(iVar5,DAT_000e0d44,uVar9);
        uVar9 = json_object_new_int(DAT_000e0de8);
        json_object_object_add(iVar5,DAT_000e0db0,uVar9);
        uVar9 = DAT_000e0dec;
        goto LAB_000e084c;
      }
      iVar10 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_000e0de4,0x20);
      json_object_object_add(iVar10,DAT_000e0d44,uVar9);
      uVar9 = json_object_new_int(DAT_000e0de8);
      json_object_object_add(iVar10,DAT_000e0db0,uVar9);
      uVar9 = DAT_000e0dec;
LAB_000e0c34:
      FCGI_printf(DAT_000e0db8,uVar9);
      qcgires_setcontenttype(iVar2,DAT_000e0d38);
      uVar9 = json_object_to_json_string(iVar10);
      FCGI_printf(DAT_000e0d48,uVar9);
LAB_000e099c:
      if (iVar10 != 0) {
        json_object_put(iVar10);
      }
    }
  }
  else {
LAB_000e0314:
    FCGI_printf(DAT_000e0d30);
    FCGI_printf(DAT_000e0d34);
    qcgires_setcontenttype(iVar2,DAT_000e0d38);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e0d3c,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e0d2c);
    uVar9 = DAT_000e0d40;
    if (iVar5 == 1) {
      uVar9 = DAT_000e0d4c;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_000e0d44,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e0d48,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000e03c4:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

