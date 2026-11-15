
void copyFromBiosCMOS_func(void)

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
  undefined4 local_1ac;
  undefined1 auStack_1a4 [44];
  undefined4 local_178;
  undefined4 uStack_174;
  undefined4 uStack_170;
  undefined4 uStack_16c;
  undefined4 local_168;
  undefined4 uStack_164;
  undefined4 uStack_160;
  undefined4 uStack_15c;
  undefined1 auStack_158 [48];
  char acStack_128 [260];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0013b20c);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0013b21c);
    FCGI_printf(DAT_0013b220);
    qcgires_setcontenttype(iVar2,DAT_0013b224);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_0013b228,uVar8);
    uVar8 = json_object_new_string(DAT_0013b22c);
    json_object_object_add(uVar9,DAT_0013b230,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_0013b234,uVar8);
    json_object_put(uVar9);
    goto LAB_0013adc0;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013b210);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0013b214,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0013b214,0);
    sVar7 = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,sVar7);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013b218), iVar5 != 0))
    goto LAB_0013ad10;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(2);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_0013b23c);
    pcVar6 = getenv(DAT_0013b240);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_0013b244),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    if (*DAT_0013b248 == 0) {
LAB_0013aeb8:
      local_178 = *DAT_0013b254;
      uStack_174 = DAT_0013b254[1];
      uStack_170 = DAT_0013b254[2];
      uStack_16c = DAT_0013b254[3];
      local_168 = DAT_0013b254[4];
      uStack_164 = DAT_0013b254[5];
      uStack_160 = DAT_0013b254[6];
      uStack_15c = DAT_0013b254[7];
      memset(auStack_158,0,0x30);
      iVar11 = json_object_object_get_rest(iVar10,DAT_0013b258);
      if (iVar11 == 0) {
LAB_0013af14:
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0013b264,DAT_0013b260,DAT_0013b25c);
        local_1ac = 0xffffffff;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_0013b258);
        iVar11 = json_object_get_int();
        if (iVar11 == 1) {
          sVar7 = strlen((char *)&local_178);
          memcpy((void *)((int)&local_178 + sVar7),DAT_0013b26c,0xe);
        }
        else if (iVar11 != 2) goto LAB_0013af14;
        sVar7 = strlen((char *)&local_178);
        memcpy((void *)((int)&local_178 + sVar7),DAT_0013b270,9);
        iVar11 = access(DAT_0013b274,0);
        if (iVar11 == 0) {
          snprintf(acStack_128,0x100,DAT_0013b278,&local_178);
          safe_system(acStack_128);
          local_1ac = 0;
        }
        else {
          local_1ac = 0xffffffff;
        }
      }
      uVar9 = json_object_new_int(local_1ac);
      json_object_object_add(iVar5,DAT_0013b268,uVar9);
      qcgires_setcontenttype(iVar2,DAT_0013b224);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0013b234,uVar9);
      IPMI_lo_Logout(auStack_1a4);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0013b244);
LAB_0013afa4:
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013b24c);
      iVar11 = IPMI_lo_Login(DAT_0013b250,DAT_0013b250,auStack_1a4,uVar1,1,0,0,0);
      if (iVar11 == 0) goto LAB_0013aeb8;
      IPMI_lo_Logout(auStack_1a4);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0013b244);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_0013b27c,0x20);
        json_object_object_add(iVar5,DAT_0013b230,uVar9);
        uVar9 = json_object_new_int(DAT_0013b280);
        json_object_object_add(iVar5,DAT_0013b284,uVar9);
        FCGI_printf(DAT_0013b28c,DAT_0013b288);
        qcgires_setcontenttype(iVar2,DAT_0013b224);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0013b234,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0013b244);
        goto LAB_0013afa4;
      }
      iVar5 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_0013b27c,0x20);
      json_object_object_add(iVar5,DAT_0013b230,uVar9);
      uVar9 = json_object_new_int(DAT_0013b280);
      json_object_object_add(iVar5,DAT_0013b284,uVar9);
      FCGI_printf(DAT_0013b28c,DAT_0013b288);
      qcgires_setcontenttype(iVar2,DAT_0013b224);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0013b234,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_0013ad10:
    FCGI_printf(DAT_0013b21c);
    FCGI_printf(DAT_0013b220);
    qcgires_setcontenttype(iVar2,DAT_0013b224);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0013b228,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0013b218);
    uVar9 = DAT_0013b22c;
    if (iVar5 == 1) {
      uVar9 = DAT_0013b238;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_0013b230,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0013b234,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0013adc0:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

