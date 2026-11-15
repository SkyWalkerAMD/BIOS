
void setHPMPrepareComponents_func(void)

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
  undefined4 uStack_10048;
  undefined4 uStack_10044;
  uint uStack_10040;
  uint uStack_1003c;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_000edf20);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000edf30);
    FCGI_printf(DAT_000edf34);
    qcgires_setcontenttype(iVar2,DAT_000edf38);
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000edf3c,uVar7);
    uVar7 = json_object_new_string(DAT_000edf40);
    json_object_object_add(uVar8,DAT_000edf44,uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000edf48,uVar7);
    json_object_put(uVar8);
    goto LAB_000eda10;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000edf24);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000edf28,0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000edf28,0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000edf2c), iVar5 != 0))
    goto LAB_000ed960;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv(DAT_000edf50);
    pcVar6 = getenv(DAT_000edf54);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_000edf58),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000edf5c);
    if (iVar10 < 4) {
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000edf60,0x16);
        json_object_object_add(iVar9,DAT_000edf44,uVar8);
        uVar8 = json_object_new_int(8000);
        json_object_object_add(iVar9,DAT_000edf64,uVar8);
        uVar8 = DAT_000edf68;
LAB_000edeb0:
        FCGI_printf(DAT_000edf6c,uVar8);
        qcgires_setcontenttype(iVar2,DAT_000edf38);
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf(DAT_000edf48,uVar8);
      }
      else {
        strcasecmp(pcVar3,DAT_000edf58);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000edf60,0x16);
        json_object_object_add(iVar5,DAT_000edf44,uVar8);
        uVar8 = json_object_new_int(8000);
        json_object_object_add(iVar5,DAT_000edf64,uVar8);
        uVar8 = DAT_000edf68;
LAB_000edb4c:
        FCGI_printf(DAT_000edf6c,uVar8);
        qcgires_setcontenttype(iVar2,DAT_000edf38);
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000edf48,uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_000edf58);
      }
LAB_000edb90:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
    else {
      iVar10 = json_object_object_get_rest(iVar9,DAT_000edf70);
      if (iVar10 == 0) {
        uStack_10040 = 0xff;
        uStack_1003c = 0xffffffff;
      }
      else {
        json_object_object_get_rest(iVar9,DAT_000edf70);
        uStack_1003c = json_object_get_int64();
        uStack_10040 = uStack_1003c & 0xff;
      }
      iVar10 = json_object_object_get_rest(iVar9,DAT_000edf74);
      if (iVar10 == 0) {
        uStack_10044 = 0xffffffff;
      }
      else {
        json_object_object_get_rest(iVar9,DAT_000edf74);
        uStack_10044 = json_object_get_int64();
      }
      iVar10 = json_object_object_get_rest(iVar9,DAT_000edf78);
      if (iVar10 == 0) {
        uStack_10048 = 0xffffffff;
      }
      else {
        json_object_object_get_rest(iVar9,DAT_000edf78);
        uStack_10048 = json_object_get_int64();
      }
      iVar10 = json_object_object_get_rest(iVar9,DAT_000edf7c);
      if (iVar10 == 0) {
        uVar1 = 0xff;
      }
      else {
        json_object_object_get_rest(iVar9,DAT_000edf7c);
        uVar1 = json_object_get_int64();
      }
      CMD_Prepare_FW_Update(auStack_10034,uStack_10048,uStack_10040,uStack_10044,uVar1,0,1);
      uVar8 = json_object_new_int(uStack_1003c);
      json_object_object_add(iVar5,DAT_000edf70,uVar8);
      uVar8 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,DAT_000edf74,uVar8);
      uVar8 = json_object_new_int(uStack_10048);
      json_object_object_add(iVar5,DAT_000edf78,uVar8);
      if (iStack_10030 != 0) {
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          iVar9 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000edf80,0x23);
          json_object_object_add(iVar9,DAT_000edf44,uVar8);
          uVar8 = json_object_new_int(DAT_000edf84);
          json_object_object_add(iVar9,DAT_000edf64,uVar8);
          uVar8 = DAT_000edf88;
          goto LAB_000edeb0;
        }
        strcasecmp(pcVar3,DAT_000edf58);
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000edf80,0x23);
        json_object_object_add(iVar5,DAT_000edf44,uVar8);
        uVar8 = json_object_new_int(DAT_000edf84);
        json_object_object_add(iVar5,DAT_000edf64,uVar8);
        uVar8 = DAT_000edf88;
        goto LAB_000edb4c;
      }
      qcgires_setcontenttype(iVar2,DAT_000edf38);
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_000edf48,uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000edf58);
        goto LAB_000edb90;
      }
    }
  }
  else {
LAB_000ed960:
    FCGI_printf(DAT_000edf30);
    FCGI_printf(DAT_000edf34);
    qcgires_setcontenttype(iVar2,DAT_000edf38);
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000edf3c,uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000edf2c);
    uVar8 = DAT_000edf40;
    if (iVar5 == 1) {
      uVar8 = DAT_000edf4c;
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,DAT_000edf44,uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000edf48,uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000eda10:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x000eda2c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

