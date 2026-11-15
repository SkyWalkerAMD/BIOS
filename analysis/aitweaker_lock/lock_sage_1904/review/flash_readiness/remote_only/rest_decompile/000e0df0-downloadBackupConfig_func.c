
void downloadBackupConfig_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *__s;
  size_t __n;
  undefined4 uVar7;
  undefined4 uVar8;
  void *__ptr;
  int iVar9;
  int iVar10;
  char local_57;
  undefined2 local_56;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_000e14a4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000e14b4);
    FCGI_printf(DAT_000e14b8);
    qcgires_setcontenttype(iVar2,DAT_000e14bc);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e14c0,uVar7);
    uVar7 = json_object_new_string(DAT_000e14c4);
    json_object_object_add(uVar8,DAT_000e14c8,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e14cc,uVar7);
    json_object_put(uVar8);
    goto LAB_000e0f68;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e14a8);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_000e0eb8:
    FCGI_printf(DAT_000e14b4);
    FCGI_printf(DAT_000e14b8);
    qcgires_setcontenttype(iVar2,DAT_000e14bc);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000e14c0,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e14b0);
    uVar8 = DAT_000e14c4;
    if (iVar5 == 1) {
      uVar8 = DAT_000e14d0;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_000e14c8,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000e14cc,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e14ac,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e14ac,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e14b0), iVar5 != 0))
    goto LAB_000e0eb8;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_000e14d4);
    pcVar6 = getenv(DAT_000e14d8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_000e14dc),
       iVar10 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_000e14e0 == 0) {
LAB_000e1060:
      local_57 = '\x0f';
      local_56 = 0;
      do {
        iVar10 = LIBIPMI_HL_AMIGetPendStatus(auStack_54,&local_57,&local_56,0x1e);
        if (iVar10 != 0) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000e14ec,DAT_000e14f0,0xa4,local_56);
          IPMI_lo_Logout(auStack_54);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 == (char *)0x0) {
            iVar5 = json_object_new_object();
            uVar7 = 0x2e;
            uVar8 = DAT_000e14f4;
            goto LAB_000e131c;
          }
          strcasecmp(pcVar3,DAT_000e14dc);
          if (iVar9 != 0) {
            json_object_put(iVar9);
          }
          iVar5 = json_object_new_object();
          uVar7 = 0x2e;
          uVar8 = DAT_000e14f4;
          goto LAB_000e111c;
        }
        sleep(1);
      } while (local_57 == '\x0f');
      if (local_57 == '\0') {
        FCGI_printf(DAT_000e1508);
        FCGI_printf(DAT_000e1510,DAT_000e150c);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          IPMI_lo_Logout(auStack_54);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          goto LAB_000e0f48;
        }
        strcasecmp(pcVar3,DAT_000e14dc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000e1514,DAT_000e14f0,0xab,local_57);
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar5 = json_object_new_object();
          uVar7 = 0x22;
          uVar8 = DAT_000e1518;
LAB_000e131c:
          uVar8 = json_object_new_string_len(uVar8,uVar7);
          json_object_object_add(iVar5,DAT_000e14c8,uVar8);
          uVar8 = json_object_new_int(DAT_000e14f8);
          json_object_object_add(iVar5,DAT_000e14fc,uVar8);
          uVar8 = DAT_000e1500;
          goto LAB_000e134c;
        }
        strcasecmp(pcVar3,DAT_000e14dc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar7 = 0x22;
        uVar8 = DAT_000e1518;
LAB_000e111c:
        uVar8 = json_object_new_string_len(uVar8,uVar7);
        json_object_object_add(iVar5,DAT_000e14c8,uVar8);
        uVar8 = json_object_new_int(DAT_000e14f8);
        json_object_object_add(iVar5,DAT_000e14fc,uVar8);
        uVar8 = DAT_000e1500;
LAB_000e114c:
        FCGI_printf(DAT_000e1504,uVar8);
        qcgires_setcontenttype(iVar2,DAT_000e14bc);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e14cc,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      strcasecmp(pcVar3,DAT_000e14dc);
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e14e4);
      iVar10 = IPMI_lo_Login(DAT_000e14e8,DAT_000e14e8,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_000e1060;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000e14dc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000e151c,0x20);
        json_object_object_add(iVar5,DAT_000e14c8,uVar8);
        uVar8 = json_object_new_int(DAT_000e1520);
        json_object_object_add(iVar5,DAT_000e14fc,uVar8);
        uVar8 = DAT_000e1524;
        goto LAB_000e114c;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000e151c,0x20);
      json_object_object_add(iVar5,DAT_000e14c8,uVar8);
      uVar8 = json_object_new_int(DAT_000e1520);
      json_object_object_add(iVar5,DAT_000e14fc,uVar8);
      uVar8 = DAT_000e1524;
LAB_000e134c:
      FCGI_printf(DAT_000e1504,uVar8);
      qcgires_setcontenttype(iVar2,DAT_000e14bc);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_000e14cc,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
LAB_000e0f48:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000e0f68:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

