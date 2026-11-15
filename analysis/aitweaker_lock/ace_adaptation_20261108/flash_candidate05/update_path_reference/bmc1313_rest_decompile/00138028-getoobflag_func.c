
void getoobflag_func(void)

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
  undefined4 local_5c;
  undefined1 local_58;
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00138568);
  pre_call_hook(iVar2);
  qcgisess_validate(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00138578);
    FCGI_printf(DAT_0013857c);
    qcgires_setcontenttype(iVar2,DAT_00138580);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00138584,uVar7);
    uVar7 = json_object_new_string(DAT_00138588);
    json_object_object_add(uVar8,DAT_0013858c,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_00138590,uVar7);
    json_object_put(uVar8);
    goto LAB_001381a8;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013856c);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00138570,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00138570,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00138574), iVar5 != 0))
    goto LAB_001380f8;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_00138598);
    pcVar6 = getenv(DAT_0013859c);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_001385a0),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_001385a4 == 0) {
LAB_001382a0:
      local_5c = 0;
      local_58 = 0;
      IPMICMD_GetOOBFlag(auStack_54,&local_5c,0x1e);
      uVar8 = json_object_new_int(local_5c._1_1_);
      json_object_object_add(iVar5,DAT_001385b0,uVar8);
      uVar8 = json_object_new_int(local_5c._2_1_);
      json_object_object_add(iVar5,DAT_001385b4,uVar8);
      uVar8 = json_object_new_int(local_5c._3_1_);
      json_object_object_add(iVar5,DAT_001385b8,uVar8);
      uVar8 = json_object_new_int(local_58);
      json_object_object_add(iVar5,DAT_001385bc,uVar8);
      qcgires_setcontenttype(iVar2,DAT_00138580);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00138590,uVar8);
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_001385a0);
LAB_00138378:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001385a8);
      iVar10 = IPMI_lo_Login(DAT_001385ac,DAT_001385ac,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_001382a0;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_001385a0);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_001385c0,0x20);
        json_object_object_add(iVar5,DAT_0013858c,uVar8);
        uVar8 = json_object_new_int(DAT_001385c4);
        json_object_object_add(iVar5,DAT_001385c8,uVar8);
        FCGI_printf(DAT_001385d0,DAT_001385cc);
        qcgires_setcontenttype(iVar2,DAT_00138580);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00138590,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_001385a0);
        goto LAB_00138378;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_001385c0,0x20);
      json_object_object_add(iVar5,DAT_0013858c,uVar8);
      uVar8 = json_object_new_int(DAT_001385c4);
      json_object_object_add(iVar5,DAT_001385c8,uVar8);
      FCGI_printf(DAT_001385d0,DAT_001385cc);
      qcgires_setcontenttype(iVar2,DAT_00138580);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_00138590,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_001380f8:
    FCGI_printf(DAT_00138578);
    FCGI_printf(DAT_0013857c);
    qcgires_setcontenttype(iVar2,DAT_00138580);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00138584,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00138574);
    uVar8 = DAT_00138588;
    if (iVar5 == 1) {
      uVar8 = DAT_00138594;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0013858c,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_00138590,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  pollqcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_001381a8:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

