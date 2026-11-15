
void trackFWTime_func(void)

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
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_000e919c);
  pre_call_hook(iVar1);
  qcgisess_validate(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_000e91ac);
    FCGI_printf(DAT_000e91b0);
    qcgires_setcontenttype(iVar1,DAT_000e91b4);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_000e91b8,uVar6);
    uVar6 = json_object_new_string(DAT_000e91bc);
    json_object_object_add(uVar7,DAT_000e91c4,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_000e91c8,uVar6);
    json_object_put(uVar7);
    goto LAB_000e8fc8;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e91a0);
  if (pcVar2 == (char *)0x0 || iVar4 != 1) {
LAB_000e8f18:
    FCGI_printf(DAT_000e91ac);
    FCGI_printf(DAT_000e91b0);
    qcgires_setcontenttype(iVar1,DAT_000e91b4);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_000e91b8,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e91a8);
    uVar7 = DAT_000e91bc;
    if (iVar4 == 1) {
      uVar7 = DAT_000e91c0;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_000e91c4,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_000e91c8,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  else {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e91a4,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_000e91a4,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_000e91a8), iVar4 != 0))
    goto LAB_000e8f18;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_000e91cc);
    pcVar5 = getenv(DAT_000e91d0);
    if ((pcVar2 == (char *)0x0) ||
       (iVar9 = strcasecmp(pcVar2,DAT_000e91d4), __ptr == (void *)0x0 || iVar9 == 0)) {
      uVar7 = json_object_new_string_len(DAT_000e91d8,2);
      json_object_object_add(iVar4,DAT_000e91dc,uVar7);
      qcgires_setcontenttype(iVar1,DAT_000e91b4);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e91c8,uVar7);
      if (iVar4 != 0) goto LAB_000e9084;
LAB_000e908c:
      if (__ptr != (void *)0x0) goto LAB_000e9190;
    }
    else {
      if (pcVar5 != (char *)0x0) {
        json_object_put(iVar8);
        iVar8 = json_tokener_parse(__ptr);
      }
      uVar7 = json_object_new_string_len(DAT_000e91d8,2);
      json_object_object_add(iVar4,DAT_000e91dc,uVar7);
      qcgires_setcontenttype(iVar1,DAT_000e91b4);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_000e91c8,uVar7);
      if (iVar4 != 0) {
LAB_000e9084:
        json_object_put(iVar4);
        goto LAB_000e908c;
      }
LAB_000e9190:
      free(__ptr);
    }
    if ((pcVar2 != (char *)0x0) && (strcasecmp(pcVar2,DAT_000e91d4), iVar8 != 0)) {
      json_object_put(iVar8);
    }
  }
  post_authorized_call_hook(iVar1,iVar3);
  pollqcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_000e8fc8:
  post_call_hook(iVar1);
                    /* WARNING: Could not recover jumptable at 0x000e8fdc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

