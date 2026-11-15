
void setoobflag_func(void)

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
  undefined1 local_6c;
  undefined2 local_64;
  undefined4 local_60;
  undefined4 uStack_5c;
  undefined1 local_58;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00137fa4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00137fb4);
    FCGI_printf(DAT_00137fb8);
    qcgires_setcontenttype(iVar2,DAT_00137fbc);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00137fc0,uVar7);
    uVar7 = json_object_new_string(DAT_00137fc4);
    json_object_object_add(uVar8,DAT_00137fc8,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00137fcc,uVar7);
    json_object_put(uVar8);
    goto LAB_00137b24;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137fa8);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00137fac,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00137fac,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137fb0), iVar5 != 0))
    goto LAB_00137a74;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(2);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_00137fd4);
    pcVar6 = getenv(DAT_00137fd8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_00137fdc),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_00137fe0 == 0) {
LAB_00137c1c:
      local_64 = 0;
      local_60 = *DAT_00137fec;
      uStack_5c = DAT_00137fec[1];
      local_58 = (undefined1)DAT_00137fec[2];
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00137ff4,DAT_00137ff8,DAT_00137ff0);
      iVar10 = json_object_object_get_rest(iVar9,DAT_00137ffc);
      if (iVar10 == 0) {
        local_6c = 0xff;
      }
      else {
        json_object_object_get_rest(iVar9,DAT_00137ffc);
        local_6c = json_object_get_int();
      }
      iVar10 = json_object_object_get_rest(iVar9,DAT_00138000);
      if (iVar10 == 0) {
        uVar1 = 0xff;
      }
      else {
        json_object_object_get_rest(iVar9,DAT_00138000);
        uVar1 = json_object_get_int();
      }
      local_64 = CONCAT11(uVar1,local_6c);
      iVar10 = IPMICMD_SetOOBFlag(auStack_54,&local_64,0x1e);
      if (iVar10 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00138024,DAT_00137ff8,DAT_00138020,iVar10);
      }
      if ((char)local_64 == '\0' && local_64._1_1_ == '\0') {
        LIBIPMI_HL_AMIMediaRedirectStartStop(auStack_54,&local_60,4,1,0,0x20,0x1e);
      }
      uVar8 = json_object_new_int((char)local_64);
      json_object_object_add(iVar5,DAT_00138004,uVar8);
      uVar8 = json_object_new_int(local_64._1_1_);
      json_object_object_add(iVar5,DAT_00138008,uVar8);
      qcgires_setcontenttype(iVar2,DAT_00137fbc);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00137fcc,uVar8);
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00137fdc);
LAB_00137d68:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137fe4);
      iVar10 = IPMI_lo_Login(DAT_00137fe8,DAT_00137fe8,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_00137c1c;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_00137fdc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0013800c,0x20);
        json_object_object_add(iVar5,DAT_00137fc8,uVar8);
        uVar8 = json_object_new_int(DAT_00138010);
        json_object_object_add(iVar5,DAT_00138014,uVar8);
        FCGI_printf(DAT_0013801c,DAT_00138018);
        qcgires_setcontenttype(iVar2,DAT_00137fbc);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00137fcc,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00137fdc);
        goto LAB_00137d68;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_0013800c,0x20);
      json_object_object_add(iVar5,DAT_00137fc8,uVar8);
      uVar8 = json_object_new_int(DAT_00138010);
      json_object_object_add(iVar5,DAT_00138014,uVar8);
      FCGI_printf(DAT_0013801c,DAT_00138018);
      qcgires_setcontenttype(iVar2,DAT_00137fbc);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00137fcc,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_00137a74:
    FCGI_printf(DAT_00137fb4);
    FCGI_printf(DAT_00137fb8);
    qcgires_setcontenttype(iVar2,DAT_00137fbc);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00137fc0,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00137fb0);
    uVar8 = DAT_00137fc4;
    if (iVar5 == 1) {
      uVar8 = DAT_00137fd0;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_00137fc8,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00137fcc,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00137b24:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

