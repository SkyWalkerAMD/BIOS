
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
  pcVar3 = getenv(DAT_000deac8);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000dead8);
    FCGI_printf(DAT_000deadc);
    qcgires_setcontenttype(iVar2,DAT_000deae0);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000deae4,uVar7);
    uVar7 = json_object_new_string(DAT_000deae8);
    json_object_object_add(uVar8,DAT_000deaec,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000deaf0,uVar7);
    json_object_put(uVar8);
    goto LAB_000de58c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000deacc);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_000de4dc:
    FCGI_printf(DAT_000dead8);
    FCGI_printf(DAT_000deadc);
    qcgires_setcontenttype(iVar2,DAT_000deae0);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000deae4,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000dead4);
    uVar8 = DAT_000deae8;
    if (iVar5 == 1) {
      uVar8 = DAT_000deaf4;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_000deaec,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000deaf0,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000dead0,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000dead0,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000dead4), iVar5 != 0))
    goto LAB_000de4dc;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_000deaf8);
    pcVar6 = getenv(DAT_000deafc);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_000deb00),
       iVar10 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_000deb04 == 0) {
LAB_000de684:
      local_57 = '\x0f';
      local_56 = 0;
      do {
        iVar10 = LIBIPMI_HL_AMIGetPendStatus(auStack_54,&local_57,&local_56,0x1e);
        if (iVar10 != 0) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000deb10,DAT_000deb14,0xab,local_56);
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
            uVar8 = DAT_000deb18;
            goto LAB_000de940;
          }
          strcasecmp(pcVar3,DAT_000deb00);
          if (iVar9 != 0) {
            json_object_put(iVar9);
          }
          iVar5 = json_object_new_object();
          uVar7 = 0x2e;
          uVar8 = DAT_000deb18;
          goto LAB_000de740;
        }
        sleep(1);
      } while (local_57 == '\x0f');
      if (local_57 == '\0') {
        FCGI_printf(DAT_000deb2c);
        FCGI_printf(DAT_000deb34,DAT_000deb30);
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
          goto LAB_000de56c;
        }
        strcasecmp(pcVar3,DAT_000deb00);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000deb38,DAT_000deb14,0xb2,local_57);
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
          uVar8 = DAT_000deb3c;
LAB_000de940:
          uVar8 = json_object_new_string_len(uVar8,uVar7);
          json_object_object_add(iVar5,DAT_000deaec,uVar8);
          uVar8 = json_object_new_int(DAT_000deb1c);
          json_object_object_add(iVar5,DAT_000deb20,uVar8);
          uVar8 = DAT_000deb24;
          goto LAB_000de970;
        }
        strcasecmp(pcVar3,DAT_000deb00);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar7 = 0x22;
        uVar8 = DAT_000deb3c;
LAB_000de740:
        uVar8 = json_object_new_string_len(uVar8,uVar7);
        json_object_object_add(iVar5,DAT_000deaec,uVar8);
        uVar8 = json_object_new_int(DAT_000deb1c);
        json_object_object_add(iVar5,DAT_000deb20,uVar8);
        uVar8 = DAT_000deb24;
LAB_000de770:
        FCGI_printf(DAT_000deb28,uVar8);
        qcgires_setcontenttype(iVar2,DAT_000deae0);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000deaf0,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      strcasecmp(pcVar3,DAT_000deb00);
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000deb08);
      iVar10 = IPMI_lo_Login(DAT_000deb0c,DAT_000deb0c,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_000de684;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000deb00);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000deb40,0x20);
        json_object_object_add(iVar5,DAT_000deaec,uVar8);
        uVar8 = json_object_new_int(DAT_000deb44);
        json_object_object_add(iVar5,DAT_000deb20,uVar8);
        uVar8 = DAT_000deb48;
        goto LAB_000de770;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000deb40,0x20);
      json_object_object_add(iVar5,DAT_000deaec,uVar8);
      uVar8 = json_object_new_int(DAT_000deb44);
      json_object_object_add(iVar5,DAT_000deb20,uVar8);
      uVar8 = DAT_000deb48;
LAB_000de970:
      FCGI_printf(DAT_000deb28,uVar8);
      qcgires_setcontenttype(iVar2,DAT_000deae0);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_000deaf0,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
LAB_000de56c:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000de58c:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

