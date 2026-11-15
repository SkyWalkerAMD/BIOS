
void putHPMExitUpdateMode_func(void)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *__s;
  size_t __n;
  undefined4 uVar6;
  undefined4 uVar7;
  void *__ptr;
  int iVar8;
  int iVar9;
  undefined1 auStack_1002c [4];
  int iStack_10028;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000ed834);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000ed844);
    FCGI_printf(DAT_000ed848);
    qcgires_setcontenttype(iVar1,DAT_000ed84c);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000ed850,uVar6);
    uVar6 = json_object_new_string(DAT_000ed854);
    json_object_object_add(uVar7,DAT_000ed858,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000ed85c,uVar6);
    json_object_put(uVar7);
    goto LAB_000ed420;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000ed838);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000ed83c,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000ed83c,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000ed840), iVar4 != 0))
    goto LAB_000ed370;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_000ed864);
    pcVar5 = getenv(DAT_000ed868);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_000ed86c),
       iVar9 != 0 && (pcVar5 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    iVar9 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000ed870);
    if (iVar9 < 4) {
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 == (char *)0x0) {
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_000ed874,0x16);
        json_object_object_add(iVar4,DAT_000ed858,uVar7);
        uVar7 = json_object_new_int(8000);
        json_object_object_add(iVar4,DAT_000ed878,uVar7);
        uVar7 = DAT_000ed87c;
LAB_000ed730:
        FCGI_printf(DAT_000ed880,uVar7);
        qcgires_setcontenttype(iVar1,DAT_000ed84c);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000ed85c,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        strcasecmp(pcVar2,DAT_000ed86c);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_000ed874,0x16);
        json_object_object_add(iVar4,DAT_000ed858,uVar7);
        uVar7 = json_object_new_int(8000);
        json_object_object_add(iVar4,DAT_000ed878,uVar7);
        uVar7 = DAT_000ed87c;
LAB_000ed55c:
        FCGI_printf(DAT_000ed880,uVar7);
        qcgires_setcontenttype(iVar1,DAT_000ed84c);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_000ed85c,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_000ed86c);
LAB_000ed5a0:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      iVar9 = json_object_object_get_rest(iVar8,DAT_000ed884);
      if (iVar9 == 0) {
        uVar7 = 0xffffffff;
      }
      else {
        json_object_object_get_rest(iVar8,DAT_000ed884);
        uVar7 = json_object_get_int64();
      }
      CMD_Exit_FW_Update_mode(auStack_1002c,uVar7);
      if (iStack_10028 != 0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar2 != (char *)0x0) {
          strcasecmp(pcVar2,DAT_000ed86c);
          if (iVar8 != 0) {
            json_object_put(iVar8);
          }
          iVar4 = json_object_new_object();
          uVar7 = json_object_new_string_len(DAT_000ed888,0x24);
          json_object_object_add(iVar4,DAT_000ed858,uVar7);
          uVar7 = json_object_new_int(DAT_000ed88c);
          json_object_object_add(iVar4,DAT_000ed878,uVar7);
          uVar7 = DAT_000ed890;
          goto LAB_000ed55c;
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_000ed888,0x24);
        json_object_object_add(iVar4,DAT_000ed858,uVar7);
        uVar7 = json_object_new_int(DAT_000ed88c);
        json_object_object_add(iVar4,DAT_000ed878,uVar7);
        uVar7 = DAT_000ed890;
        goto LAB_000ed730;
      }
      uVar7 = json_object_new_int();
      json_object_object_add(iVar4,DAT_000ed850,uVar7);
      qcgires_setcontenttype(iVar1,DAT_000ed84c);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000ed85c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_000ed86c);
        goto LAB_000ed5a0;
      }
    }
  }
  else {
LAB_000ed370:
    FCGI_printf(DAT_000ed844);
    FCGI_printf(DAT_000ed848);
    qcgires_setcontenttype(iVar1,DAT_000ed84c);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_000ed850,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000ed840);
    uVar7 = DAT_000ed854;
    if (iVar4 == 1) {
      uVar7 = DAT_000ed860;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_000ed858,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_000ed85c,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000ed420:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x000ed43c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

