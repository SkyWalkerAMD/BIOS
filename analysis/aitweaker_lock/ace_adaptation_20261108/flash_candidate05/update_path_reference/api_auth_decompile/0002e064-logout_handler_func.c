
void logout_handler_func(void)

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
  char local_55;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0002e750);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0002e760);
    FCGI_printf(DAT_0002e764);
    qcgires_setcontenttype(iVar2,DAT_0002e768);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0002e76c,uVar7);
    uVar7 = json_object_new_string(DAT_0002e770);
    json_object_object_add(uVar8,DAT_0002e774,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0002e778,uVar7);
    json_object_put(uVar8);
    goto LAB_0002e1bc;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0002e754);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0002e758,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0002e758,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 == 0) && (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0002e75c), iVar5 == 0)) {
      pre_authorized_call_hook(iVar2,iVar4);
      iVar5 = json_object_new_object();
      __ptr = (void *)qcgireq_getquery(5);
      iVar9 = json_object_new_object();
      pcVar3 = getenv(DAT_0002e780);
      pcVar6 = getenv(DAT_0002e784);
      if ((pcVar3 != (char *)0x0) &&
         (iVar10 = strcasecmp(pcVar3,DAT_0002e788),
         iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
        json_object_put(iVar9);
        iVar9 = json_tokener_parse(__ptr);
      }
      if (*DAT_0002e78c == 0) {
LAB_0002e2b4:
        local_55 = '\0';
        qcgisess_getid(iVar4);
        iVar10 = getViewerCount();
        if (0 < iVar10) {
          qcgisess_getid(iVar4);
          WritePipeData();
        }
        if (*(int *)(DAT_0002e798 + 0x1e0) != 1) {
          iVar10 = get_active_session(0,&local_55);
          if (iVar10 == 0) {
            if (local_55 != '\0') {
              local_55 = local_55 + -1;
            }
            iVar10 = set_active_session(0);
            if (iVar10 == 0) goto LAB_0002e324;
            IPMI_lo_Logout(auStack_54);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 == (char *)0x0) {
              iVar4 = json_object_new_object();
              uVar8 = json_object_new_string_len(DAT_0002e7a4,0x26);
              json_object_object_add(iVar4,DAT_0002e774,uVar8);
              uVar8 = DAT_0002e7a8;
              goto LAB_0002e68c;
            }
            strcasecmp(pcVar3,DAT_0002e788);
            if (iVar9 != 0) {
              json_object_put(iVar9);
            }
            iVar4 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_0002e7a4,0x26);
            json_object_object_add(iVar4,DAT_0002e774,uVar8);
            uVar8 = DAT_0002e7a8;
          }
          else {
            IPMI_lo_Logout(auStack_54);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 == (char *)0x0) {
              iVar4 = json_object_new_object();
              uVar8 = json_object_new_string_len(DAT_0002e7c8,0x26);
              json_object_object_add(iVar4,DAT_0002e774,uVar8);
              uVar8 = DAT_0002e7cc;
LAB_0002e68c:
              uVar8 = json_object_new_int(uVar8);
              json_object_object_add(iVar4,DAT_0002e7ac,uVar8);
              uVar8 = DAT_0002e7b0;
              goto LAB_0002e6a4;
            }
            strcasecmp(pcVar3,DAT_0002e788);
            if (iVar9 != 0) {
              json_object_put(iVar9);
            }
            iVar4 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_0002e7c8,0x26);
            json_object_object_add(iVar4,DAT_0002e774,uVar8);
            uVar8 = DAT_0002e7cc;
          }
          uVar8 = json_object_new_int(uVar8);
          json_object_object_add(iVar4,DAT_0002e7ac,uVar8);
          uVar8 = DAT_0002e7b0;
          goto LAB_0002e4cc;
        }
        uVar8 = (**(code **)(iVar2 + 0x24))(iVar4,DAT_0002e7b8);
        racsessinfo_unregister_session(uVar8,1);
LAB_0002e324:
        iVar10 = (**(code **)(iVar2 + 0x24))(iVar4,DAT_0002e79c);
        if (iVar10 != 0) {
          WebAuditLogout(iVar10,1);
        }
        qcgisess_destroy(iVar4);
        uVar8 = json_object_new_int(0);
        json_object_object_add(iVar5,DAT_0002e7a0,uVar8);
        qcgires_setcontenttype(iVar2,DAT_0002e768);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0002e778,uVar8);
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) goto LAB_0002e1bc;
        strcasecmp(pcVar3,DAT_0002e788);
      }
      else {
        uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0002e790);
        iVar10 = IPMI_lo_Login(DAT_0002e794,DAT_0002e794,auStack_54,uVar1,1,0,0,0);
        if (iVar10 == 0) goto LAB_0002e2b4;
        IPMI_lo_Logout(auStack_54);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar4 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_0002e7bc,0x20);
          json_object_object_add(iVar4,DAT_0002e774,uVar8);
          uVar8 = json_object_new_int(DAT_0002e7c0);
          json_object_object_add(iVar4,DAT_0002e7ac,uVar8);
          uVar8 = DAT_0002e7c4;
LAB_0002e6a4:
          FCGI_printf(DAT_0002e7b4,uVar8);
          qcgires_setcontenttype(iVar2,DAT_0002e768);
          uVar8 = json_object_to_json_string(iVar4);
          FCGI_printf(DAT_0002e778,uVar8);
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
          goto LAB_0002e1bc;
        }
        strcasecmp(pcVar3,DAT_0002e788);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar4 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0002e7bc,0x20);
        json_object_object_add(iVar4,DAT_0002e774,uVar8);
        uVar8 = json_object_new_int(DAT_0002e7c0);
        json_object_object_add(iVar4,DAT_0002e7ac,uVar8);
        uVar8 = DAT_0002e7c4;
LAB_0002e4cc:
        FCGI_printf(DAT_0002e7b4,uVar8);
        qcgires_setcontenttype(iVar2,DAT_0002e768);
        uVar8 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0002e778,uVar8);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar3,DAT_0002e788);
      }
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
      goto LAB_0002e1bc;
    }
  }
  FCGI_printf(DAT_0002e760);
  FCGI_printf(DAT_0002e764);
  qcgires_setcontenttype(iVar2,DAT_0002e768);
  uVar7 = json_object_new_object();
  uVar8 = json_object_new_int(7);
  json_object_object_add(uVar7,DAT_0002e76c,uVar8);
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0002e75c);
  uVar8 = DAT_0002e770;
  if (iVar5 == 1) {
    uVar8 = DAT_0002e77c;
  }
  uVar8 = json_object_new_string(uVar8);
  json_object_object_add(uVar7,DAT_0002e774,uVar8);
  uVar8 = json_object_to_json_string(uVar7);
  FCGI_printf(DAT_0002e778,uVar8);
  json_object_put(uVar7);
  qcgisess_clear(iVar4);
LAB_0002e1bc:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

