
void setBIOSPrepareComponents_func(void)

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
  int iVar11;
  uint uVar12;
  undefined4 uStack_10068;
  undefined4 uStack_10064;
  uint uStack_10060;
  uint uStack_1005c;
  undefined1 uStack_10055;
  char acStack_10054 [32];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_001338b0);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_001338c0);
    FCGI_printf(DAT_001338c4);
    qcgires_setcontenttype(iVar2,DAT_001338c8);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_001338cc,uVar7);
    uVar7 = json_object_new_string(DAT_001338d0);
    json_object_object_add(uVar8,DAT_001338d4,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_001338d8,uVar7);
    json_object_put(uVar8);
    goto LAB_001333ac;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001338b4);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001338b8,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_001338b8,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001338bc), iVar5 != 0))
    goto LAB_001332fc;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_001338e0);
    pcVar6 = getenv(DAT_001338e4);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_001338e8),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    uStack_10055 = 1;
    memset(acStack_10054,0,0x20);
    iVar10 = FCGI_fopen(DAT_001338f0,DAT_001338ec);
    if (iVar10 != 0) {
      FCGI_fwrite(&uStack_10055,1,1,iVar10);
    }
    unlink(DAT_001338f4);
    iVar11 = json_object_object_get_rest(iVar9,DAT_001338f8);
    if (iVar11 == 0) {
      uStack_10060 = 0xff;
      uStack_1005c = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_001338f8);
      uStack_1005c = json_object_get_int64();
      uStack_10060 = uStack_1005c & 0xff;
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_001338fc);
    if (iVar11 == 0) {
      uStack_10064 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_001338fc);
      uStack_10064 = json_object_get_int64();
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_00133900);
    if (iVar11 == 0) {
      uStack_10068 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133900);
      uStack_10068 = json_object_get_int64();
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_00133904);
    if (iVar11 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133904);
      uVar1 = json_object_get_int64();
    }
    iVar11 = json_object_object_get_rest(iVar9,DAT_00133908);
    if (iVar11 == 0) {
      uVar12 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,DAT_00133908);
      uVar12 = json_object_get_int64();
      uVar12 = uVar12 & 0xff;
    }
    snprintf(acStack_10054,0x20,DAT_0013390c,uVar12);
    safe_system(acStack_10054);
    CMD_Prepare_FW_Update(auStack_10034,uStack_10068,uStack_10060,uStack_10064,uVar1,0,1);
    uVar8 = json_object_new_int(uStack_1005c);
    json_object_object_add(iVar5,DAT_001338f8,uVar8);
    uVar8 = json_object_new_int(uStack_10064);
    json_object_object_add(iVar5,DAT_001338fc,uVar8);
    uVar8 = json_object_new_int(uStack_10068);
    json_object_object_add(iVar5,DAT_00133900,uVar8);
    if (iStack_10030 == 0) {
      if (iVar10 != 0) {
        FCGI_fclose(iVar10);
      }
      qcgires_setcontenttype(iVar2,DAT_001338c8);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_001338d8,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_001338e8);
        goto LAB_00133708;
      }
    }
    else {
      if (iVar10 != 0) {
        uStack_10055 = 0;
        FCGI_fwrite(&uStack_10055,1,1,iVar10);
        FCGI_fclose(iVar10);
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00133910,0x1f);
        json_object_object_add(iVar9,DAT_001338d4,uVar8);
        uVar8 = json_object_new_int(DAT_00133914);
        json_object_object_add(iVar9,DAT_00133918,uVar8);
        FCGI_printf(DAT_00133920,DAT_0013391c);
        qcgires_setcontenttype(iVar2,DAT_001338c8);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_001338d8,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_001338e8);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_00133910,0x1f);
        json_object_object_add(iVar5,DAT_001338d4,uVar8);
        uVar8 = json_object_new_int(DAT_00133914);
        json_object_object_add(iVar5,DAT_00133918,uVar8);
        FCGI_printf(DAT_00133920,DAT_0013391c);
        qcgires_setcontenttype(iVar2,DAT_001338c8);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_001338d8,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_001338e8);
      }
LAB_00133708:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_001332fc:
    FCGI_printf(DAT_001338c0);
    FCGI_printf(DAT_001338c4);
    qcgires_setcontenttype(iVar2,DAT_001338c8);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_001338cc,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_001338bc);
    uVar8 = DAT_001338d0;
    if (iVar5 == 1) {
      uVar8 = DAT_001338dc;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_001338d4,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_001338d8,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_001333ac:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

