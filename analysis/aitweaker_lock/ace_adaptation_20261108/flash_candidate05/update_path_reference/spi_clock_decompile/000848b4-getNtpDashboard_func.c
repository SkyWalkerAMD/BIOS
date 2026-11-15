
void getNtpDashboard_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *__s;
  size_t sVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  int iVar11;
  int local_98;
  undefined1 auStack_94 [44];
  char acStack_68 [68];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00084f88);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00084f98);
    FCGI_printf(DAT_00084f9c);
    qcgires_setcontenttype(iVar2,DAT_00084fa0);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00084fa4,uVar8);
    uVar8 = json_object_new_string(DAT_00084fa8);
    json_object_object_add(uVar9,DAT_00084fac,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_00084fb0,uVar8);
    json_object_put(uVar9);
    goto LAB_00084a2c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00084f8c);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00084f90,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00084f90,0);
    sVar7 = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,sVar7);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00084f94), iVar5 != 0))
    goto LAB_0008497c;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_00084fb8);
    pcVar6 = getenv(DAT_00084fbc);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_00084fc0),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    if (*DAT_00084fc4 == 0) {
LAB_00084b24:
      uVar9 = json_object_new_int(1);
      json_object_object_add(iVar5,DAT_00084fd0,uVar9);
      if (*(int *)(DAT_00084fd4 + 0x140) == 1) {
        iVar11 = IPMICMD_GetSELTimeUTCOffset(auStack_94,&local_98,0x1e);
        if (iVar11 == 0) {
          uVar9 = json_object_new_int((local_98 << 8) >> 0x10);
          json_object_object_add(iVar5,DAT_00084ff0,uVar9);
          goto LAB_00084b4c;
        }
        IPMI_lo_Logout(auStack_94);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar5 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_00084fd8,0x20);
          json_object_object_add(iVar5,DAT_00084fac,uVar9);
          uVar9 = 0x3f8;
          goto LAB_00084d68;
        }
        strcasecmp(pcVar3,DAT_00084fc0);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_00084fd8,0x20);
        json_object_object_add(iVar5,DAT_00084fac,uVar9);
        uVar9 = 0x3f8;
LAB_00084bd8:
        uVar9 = json_object_new_int(uVar9);
        json_object_object_add(iVar5,DAT_00084fe0,uVar9);
        uVar9 = DAT_00084fe4;
LAB_00084bf0:
        FCGI_printf(DAT_00084fe8,uVar9);
        qcgires_setcontenttype(iVar2,DAT_00084fa0);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00084fb0,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00084fc0);
      }
      else {
LAB_00084b4c:
        iVar11 = LIBIPMI_HL_AMIGetTimeZone(auStack_94,acStack_68,0x1e);
        if (iVar11 != 0) {
          IPMI_lo_Logout(auStack_94);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 == (char *)0x0) {
            iVar5 = json_object_new_object();
            uVar9 = json_object_new_string_len(DAT_00084fd8,0x20);
            json_object_object_add(iVar5,DAT_00084fac,uVar9);
            uVar9 = DAT_00084fdc;
LAB_00084d68:
            uVar9 = json_object_new_int(uVar9);
            json_object_object_add(iVar5,DAT_00084fe0,uVar9);
            uVar9 = DAT_00084fe4;
            goto LAB_00084d80;
          }
          strcasecmp(pcVar3,DAT_00084fc0);
          if (iVar10 != 0) {
            json_object_put(iVar10);
          }
          iVar5 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_00084fd8,0x20);
          json_object_object_add(iVar5,DAT_00084fac,uVar9);
          uVar9 = DAT_00084fdc;
          goto LAB_00084bd8;
        }
        sVar7 = strlen(acStack_68);
        uVar9 = json_object_new_string_len(acStack_68,sVar7);
        json_object_object_add(iVar5,DAT_00084fec,uVar9);
        qcgires_setcontenttype(iVar2,DAT_00084fa0);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00084fb0,uVar9);
        IPMI_lo_Logout(auStack_94);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) goto LAB_00084a0c;
        strcasecmp(pcVar3,DAT_00084fc0);
      }
      if (iVar10 != 0) {
        json_object_put(iVar10);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00084fc8);
      iVar11 = IPMI_lo_Login(DAT_00084fcc,DAT_00084fcc,auStack_94,uVar1,1,0,0,0);
      if (iVar11 == 0) goto LAB_00084b24;
      IPMI_lo_Logout(auStack_94);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00084fc0);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_00084ff4,0x20);
        json_object_object_add(iVar5,DAT_00084fac,uVar9);
        uVar9 = json_object_new_int(DAT_00084ff8);
        json_object_object_add(iVar5,DAT_00084fe0,uVar9);
        uVar9 = DAT_00084ffc;
        goto LAB_00084bf0;
      }
      iVar5 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_00084ff4,0x20);
      json_object_object_add(iVar5,DAT_00084fac,uVar9);
      uVar9 = json_object_new_int(DAT_00084ff8);
      json_object_object_add(iVar5,DAT_00084fe0,uVar9);
      uVar9 = DAT_00084ffc;
LAB_00084d80:
      FCGI_printf(DAT_00084fe8,uVar9);
      qcgires_setcontenttype(iVar2,DAT_00084fa0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00084fb0,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_0008497c:
    FCGI_printf(DAT_00084f98);
    FCGI_printf(DAT_00084f9c);
    qcgires_setcontenttype(iVar2,DAT_00084fa0);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00084fa4,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00084f94);
    uVar9 = DAT_00084fa8;
    if (iVar5 == 1) {
      uVar9 = DAT_00084fb4;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_00084fac,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00084fb0,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
LAB_00084a0c:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00084a2c:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

