
void downloadUserProfile_v2_func(void)

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
  undefined1 auStack_d4 [44];
  undefined4 local_a8;
  undefined4 uStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 uStack_78;
  undefined1 local_74;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0013a5a4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0013a5b4);
    FCGI_printf(DAT_0013a5b8);
    qcgires_setcontenttype(iVar2,DAT_0013a5bc);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0013a5c0,uVar7);
    uVar7 = json_object_new_string(DAT_0013a5c4);
    json_object_object_add(uVar8,DAT_0013a5c8,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0013a5cc,uVar7);
    json_object_put(uVar8);
    goto LAB_0013a0c4;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013a5a8);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0013a5ac,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0013a5ac,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013a5b0), iVar5 != 0))
    goto LAB_0013a014;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(2);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0013a5d4);
    pcVar6 = getenv(DAT_0013a5d8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0013a5dc),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_0013a5e0 == 0) {
LAB_0013a1bc:
      memset(&local_a8,0,0x80);
      json_object_object_get_rest(iVar9,DAT_0013a5ec);
      uVar8 = json_object_get_string();
      local_a8 = *DAT_0013a5f0;
      uStack_a4 = DAT_0013a5f0[1];
      uStack_a0 = DAT_0013a5f0[2];
      uStack_9c = DAT_0013a5f0[3];
      local_98 = DAT_0013a5f0[4];
      uStack_94 = DAT_0013a5f0[5];
      uStack_90 = DAT_0013a5f0[6];
      uStack_8c = DAT_0013a5f0[7];
      local_88 = DAT_0013a5f0[8];
      uStack_84 = DAT_0013a5f0[9];
      uStack_80 = DAT_0013a5f0[10];
      uStack_7c = DAT_0013a5f0[0xb];
      uStack_78 = DAT_0013a5f0[0xc];
      local_74 = (undefined1)DAT_0013a5f0[0xd];
      safe_system(&local_a8);
      snprintf((char *)&local_a8,0x80,DAT_0013a5f4,uVar8);
      safe_system(&local_a8);
      iVar10 = access(DAT_0013a5f8,0);
      if (iVar10 == 0) {
        FCGI_printf(DAT_0013a610);
        FCGI_printf(DAT_0013a614,DAT_0013a5f8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          IPMI_lo_Logout(auStack_d4);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          goto LAB_0013a0a4;
        }
        strcasecmp(pcVar3,DAT_0013a5dc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        IPMI_lo_Logout(auStack_d4);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0013a5dc);
      }
      else {
        IPMI_lo_Logout(auStack_d4);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar5 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_0013a5fc,0x26);
          json_object_object_add(iVar5,DAT_0013a5c8,uVar8);
          uVar8 = json_object_new_int(DAT_0013a600);
          json_object_object_add(iVar5,DAT_0013a604,uVar8);
          uVar8 = DAT_0013a608;
          goto LAB_0013a460;
        }
        strcasecmp(pcVar3,DAT_0013a5dc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0013a5fc,0x26);
        json_object_object_add(iVar5,DAT_0013a5c8,uVar8);
        uVar8 = json_object_new_int(DAT_0013a600);
        json_object_object_add(iVar5,DAT_0013a604,uVar8);
        uVar8 = DAT_0013a608;
LAB_0013a2d4:
        FCGI_printf(DAT_0013a60c,uVar8);
        qcgires_setcontenttype(iVar2,DAT_0013a5bc);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0013a5cc,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0013a5dc);
      }
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013a5e4);
      iVar10 = IPMI_lo_Login(DAT_0013a5e8,DAT_0013a5e8,auStack_d4,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_0013a1bc;
      IPMI_lo_Logout(auStack_d4);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0013a5dc);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0013a618,0x20);
        json_object_object_add(iVar5,DAT_0013a5c8,uVar8);
        uVar8 = json_object_new_int(DAT_0013a61c);
        json_object_object_add(iVar5,DAT_0013a604,uVar8);
        uVar8 = DAT_0013a620;
        goto LAB_0013a2d4;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_0013a618,0x20);
      json_object_object_add(iVar5,DAT_0013a5c8,uVar8);
      uVar8 = json_object_new_int(DAT_0013a61c);
      json_object_object_add(iVar5,DAT_0013a604,uVar8);
      uVar8 = DAT_0013a620;
LAB_0013a460:
      FCGI_printf(DAT_0013a60c,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0013a5bc);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0013a5cc,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_0013a014:
    FCGI_printf(DAT_0013a5b4);
    FCGI_printf(DAT_0013a5b8);
    qcgires_setcontenttype(iVar2,DAT_0013a5bc);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0013a5c0,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013a5b0);
    uVar8 = DAT_0013a5c4;
    if (iVar5 == 1) {
      uVar8 = DAT_0013a5d0;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0013a5c8,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0013a5cc,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
LAB_0013a0a4:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0013a0c4:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

