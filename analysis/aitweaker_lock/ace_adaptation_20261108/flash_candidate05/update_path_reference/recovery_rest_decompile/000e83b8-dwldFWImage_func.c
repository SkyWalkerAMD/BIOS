
void dwldFWImage_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t __n;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  int iVar11;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_000e8894);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000e88a4);
    FCGI_printf(DAT_000e88a8);
    qcgires_setcontenttype(iVar2,DAT_000e88ac);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_000e88b0,uVar8);
    uVar8 = json_object_new_string(DAT_000e88b4);
    json_object_object_add(uVar9,DAT_000e88b8,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_000e88bc,uVar8);
    json_object_put(uVar9);
    goto LAB_000e8530;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e8898);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e889c,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e889c,0);
    __n = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e88a0), iVar5 != 0))
    goto LAB_000e8480;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar10 = json_object_new_object();
    pcVar3 = getenv(DAT_000e88c4);
    pcVar6 = getenv(DAT_000e88c8);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_000e88cc),
       iVar11 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar10);
      iVar10 = json_tokener_parse(__ptr);
    }
    iVar11 = json_object_object_get_rest(iVar10,DAT_000e88d0);
    if (iVar11 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar10,DAT_000e88d0);
      uVar1 = json_object_get_int();
    }
    iVar11 = DownloadFwImage(uVar1);
    if (iVar11 == 0) {
      pcVar6 = getenv(DAT_000e88c4);
      pcVar7 = getenv(DAT_000e88c8);
      if (((pcVar6 != (char *)0x0 && pcVar7 != (char *)0x0) &&
          (iVar11 = strcasecmp(pcVar6,DAT_000e88cc), iVar11 != 0)) &&
         (iVar11 = strncasecmp(pcVar7,DAT_000e88ac,0x10), iVar11 == 0)) {
        qcgires_setcontenttype(iVar2,DAT_000e88ac);
        uVar9 = json_object_to_json_string(iVar10);
        FCGI_printf(DAT_000e88bc,uVar9);
      }
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000e88cc);
        goto LAB_000e86cc;
      }
    }
    else {
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e88d4,0x23);
        json_object_object_add(iVar5,DAT_000e88b8,uVar9);
        uVar9 = json_object_new_int(iVar11);
        json_object_object_add(iVar5,DAT_000e88d8,uVar9);
        FCGI_printf(DAT_000e88e0,DAT_000e88dc);
        qcgires_setcontenttype(iVar2,DAT_000e88ac);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e88bc,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
      }
      else {
        strcasecmp(pcVar3,DAT_000e88cc);
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e88d4,0x23);
        json_object_object_add(iVar5,DAT_000e88b8,uVar9);
        uVar9 = json_object_new_int(iVar11);
        json_object_object_add(iVar5,DAT_000e88d8,uVar9);
        FCGI_printf(DAT_000e88e0,DAT_000e88dc);
        qcgires_setcontenttype(iVar2,DAT_000e88ac);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e88bc,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_000e88cc);
LAB_000e86cc:
        if (iVar10 != 0) {
          json_object_put(iVar10);
        }
      }
    }
  }
  else {
LAB_000e8480:
    FCGI_printf(DAT_000e88a4);
    FCGI_printf(DAT_000e88a8);
    qcgires_setcontenttype(iVar2,DAT_000e88ac);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e88b0,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e88a0);
    uVar9 = DAT_000e88b4;
    if (iVar5 == 1) {
      uVar9 = DAT_000e88c0;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_000e88b8,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e88bc,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000e8530:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x000e8548. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

