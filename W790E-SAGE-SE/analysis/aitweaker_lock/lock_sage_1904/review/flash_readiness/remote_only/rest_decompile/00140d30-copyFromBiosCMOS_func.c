
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
  pcVar3 = getenv(DAT_001412f4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00141304);
    FCGI_printf(DAT_00141308);
    qcgires_setcontenttype(iVar2,DAT_0014130c);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00141310,uVar8);
    uVar8 = json_object_new_string(DAT_00141314);
    json_object_object_add(uVar9,DAT_00141318,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_0014131c,uVar8);
    json_object_put(uVar9);
    goto LAB_00140ea8;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001412f8);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001412fc,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001412fc,0);
    sVar7 = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,sVar7);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00141300), iVar5 != 0))
    goto LAB_00140df8;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(2);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_00141324);
    pcVar6 = getenv(DAT_00141328);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_0014132c),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    if (*DAT_00141330 == 0) {
LAB_00140fa0:
      local_178 = *DAT_0014133c;
      uStack_174 = DAT_0014133c[1];
      uStack_170 = DAT_0014133c[2];
      uStack_16c = DAT_0014133c[3];
      local_168 = DAT_0014133c[4];
      uStack_164 = DAT_0014133c[5];
      uStack_160 = DAT_0014133c[6];
      uStack_15c = DAT_0014133c[7];
      memset(auStack_158,0,0x30);
      iVar11 = json_object_object_get_rest(iVar10,DAT_00141340);
      if (iVar11 == 0) {
LAB_00140ffc:
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0014134c,DAT_00141348,DAT_00141344);
        local_1ac = 0xffffffff;
      }
      else {
        json_object_object_get_rest(iVar10,DAT_00141340);
        iVar11 = json_object_get_int64();
        if (iVar11 == 1) {
          sVar7 = strlen((char *)&local_178);
          memcpy((void *)((int)&local_178 + sVar7),DAT_00141354,0xe);
        }
        else if (iVar11 != 2) goto LAB_00140ffc;
        sVar7 = strlen((char *)&local_178);
        memcpy((void *)((int)&local_178 + sVar7),DAT_00141358,9);
        iVar11 = access(DAT_0014135c,0);
        if (iVar11 == 0) {
          snprintf(acStack_128,0x100,DAT_00141360,&local_178);
          safe_system(acStack_128);
          local_1ac = 0;
        }
        else {
          local_1ac = 0xffffffff;
        }
      }
      uVar9 = json_object_new_int(local_1ac);
      json_object_object_add(iVar5,DAT_00141350,uVar9);
      qcgires_setcontenttype(iVar2,DAT_0014130c);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0014131c,uVar9);
      IPMI_lo_Logout(auStack_1a4);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0014132c);
LAB_0014108c:
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00141334);
      iVar11 = IPMI_lo_Login(DAT_00141338,DAT_00141338,auStack_1a4,uVar1,1,0,0,0);
      if (iVar11 == 0) goto LAB_00140fa0;
      IPMI_lo_Logout(auStack_1a4);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0014132c);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_00141364,0x20);
        json_object_object_add(iVar5,DAT_00141318,uVar9);
        uVar9 = json_object_new_int(DAT_00141368);
        json_object_object_add(iVar5,DAT_0014136c,uVar9);
        FCGI_printf(DAT_00141374,DAT_00141370);
        qcgires_setcontenttype(iVar2,DAT_0014130c);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0014131c,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0014132c);
        goto LAB_0014108c;
      }
      iVar5 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_00141364,0x20);
      json_object_object_add(iVar5,DAT_00141318,uVar9);
      uVar9 = json_object_new_int(DAT_00141368);
      json_object_object_add(iVar5,DAT_0014136c,uVar9);
      FCGI_printf(DAT_00141374,DAT_00141370);
      qcgires_setcontenttype(iVar2,DAT_0014130c);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0014131c,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  else {
LAB_00140df8:
    FCGI_printf(DAT_00141304);
    FCGI_printf(DAT_00141308);
    qcgires_setcontenttype(iVar2,DAT_0014130c);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_00141310,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00141300);
    uVar9 = DAT_00141314;
    if (iVar5 == 1) {
      uVar9 = DAT_00141320;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_00141318,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0014131c,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00140ea8:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

