
void GetFeatureList_func(void)

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
  undefined1 uStack_8d;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined1 local_78;
  undefined1 local_77;
  undefined1 auStack_74 [32];
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0014aacc);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0014aadc);
    FCGI_printf(DAT_0014aae0);
    qcgires_setcontenttype(iVar2,DAT_0014aae4);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0014aae8,uVar7);
    uVar7 = json_object_new_string(DAT_0014aaec);
    json_object_object_add(uVar8,DAT_0014aaf0,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0014aaf4,uVar7);
    json_object_put(uVar8);
    goto LAB_0014a51c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014aad0);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0014aad4,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0014aad4,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014aad8), iVar5 != 0))
    goto LAB_0014a46c;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_0014aafc);
    pcVar6 = getenv(DAT_0014ab00);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0014ab04),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    if (*DAT_0014ab08 == 0) {
LAB_0014a614:
      memset(auStack_74,0,0x20);
      local_8c = 0;
      local_88 = 0;
      local_84 = 0;
      local_80 = 0;
      local_7c = 0;
      local_78 = 0;
      iVar10 = LIBIPMI_HL_GetSetFeatureList(auStack_54,auStack_74,0,&local_8c,&uStack_8d,0x1e);
      if (iVar10 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0014ab84,DAT_0014ab80,DAT_0014ab7c,iVar10);
      }
      uVar8 = json_object_new_int(local_8c._1_1_);
      json_object_object_add(iVar5,DAT_0014ab14,uVar8);
      uVar8 = json_object_new_int(local_8c._2_1_);
      json_object_object_add(iVar5,DAT_0014ab18,uVar8);
      uVar8 = json_object_new_int(local_8c._3_1_);
      json_object_object_add(iVar5,DAT_0014ab1c,uVar8);
      uVar8 = json_object_new_int(local_88 & 0xff);
      json_object_object_add(iVar5,DAT_0014ab20,uVar8);
      uVar8 = json_object_new_int(local_88._1_1_);
      json_object_object_add(iVar5,DAT_0014ab24,uVar8);
      uVar8 = json_object_new_int(local_88._2_1_);
      json_object_object_add(iVar5,DAT_0014ab28,uVar8);
      uVar8 = json_object_new_int(local_88._3_1_);
      json_object_object_add(iVar5,DAT_0014ab2c,uVar8);
      uVar8 = json_object_new_int(local_84 & 0xff);
      json_object_object_add(iVar5,DAT_0014ab30,uVar8);
      uVar8 = json_object_new_int(local_84._1_1_);
      json_object_object_add(iVar5,DAT_0014ab34,uVar8);
      uVar8 = json_object_new_int(local_84._2_1_);
      json_object_object_add(iVar5,DAT_0014ab38,uVar8);
      uVar8 = json_object_new_int(local_84._3_1_);
      json_object_object_add(iVar5,DAT_0014ab3c,uVar8);
      uVar8 = json_object_new_int(local_80 & 0xff);
      json_object_object_add(iVar5,DAT_0014ab40,uVar8);
      uVar8 = json_object_new_int(local_80._1_1_);
      json_object_object_add(iVar5,DAT_0014ab44,uVar8);
      uVar8 = json_object_new_int(local_80._2_1_);
      json_object_object_add(iVar5,DAT_0014ab48,uVar8);
      uVar8 = json_object_new_int(local_80._3_1_);
      json_object_object_add(iVar5,DAT_0014ab4c,uVar8);
      uVar8 = json_object_new_int(local_7c & 0xff);
      json_object_object_add(iVar5,DAT_0014ab50,uVar8);
      uVar8 = json_object_new_int(local_7c._1_1_);
      json_object_object_add(iVar5,DAT_0014ab54,uVar8);
      uVar8 = json_object_new_int(local_7c._2_1_);
      json_object_object_add(iVar5,DAT_0014ab58,uVar8);
      uVar8 = json_object_new_int(local_7c._3_1_);
      json_object_object_add(iVar5,DAT_0014ab5c,uVar8);
      uVar8 = json_object_new_int(local_78);
      json_object_object_add(iVar5,DAT_0014ab60,uVar8);
      uVar8 = json_object_new_int(local_77);
      json_object_object_add(iVar5,DAT_0014ab64,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0014aae4);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0014aaf4,uVar8);
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0014ab04);
LAB_0014a8c0:
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014ab0c);
      iVar10 = IPMI_lo_Login(DAT_0014ab10,DAT_0014ab10,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_0014a614;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0014ab04);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_0014ab68,0x20);
        json_object_object_add(iVar5,DAT_0014aaf0,uVar8);
        uVar8 = json_object_new_int(DAT_0014ab6c);
        json_object_object_add(iVar5,DAT_0014ab70,uVar8);
        FCGI_printf(DAT_0014ab78,DAT_0014ab74);
        qcgires_setcontenttype(iVar2,DAT_0014aae4);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0014aaf4,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0014ab04);
        goto LAB_0014a8c0;
      }
      iVar5 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_0014ab68,0x20);
      json_object_object_add(iVar5,DAT_0014aaf0,uVar8);
      uVar8 = json_object_new_int(DAT_0014ab6c);
      json_object_object_add(iVar5,DAT_0014ab70,uVar8);
      FCGI_printf(DAT_0014ab78,DAT_0014ab74);
      qcgires_setcontenttype(iVar2,DAT_0014aae4);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0014aaf4,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_0014a46c:
    FCGI_printf(DAT_0014aadc);
    FCGI_printf(DAT_0014aae0);
    qcgires_setcontenttype(iVar2,DAT_0014aae4);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0014aae8,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014aad8);
    uVar8 = DAT_0014aaec;
    if (iVar5 == 1) {
      uVar8 = DAT_0014aaf8;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_0014aaf0,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0014aaf4,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0014a51c:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

