
void putBIOSExitUpdateMode_func(void)

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
  undefined1 uStack_10135;
  undefined4 uStack_10134;
  undefined4 uStack_10130;
  undefined4 uStack_1012c;
  undefined4 uStack_10128;
  undefined4 uStack_10124;
  undefined4 uStack_10120;
  undefined4 uStack_1011c;
  undefined2 uStack_10118;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_0012c3b8);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_0012c3c8);
    FCGI_printf(DAT_0012c3cc);
    qcgires_setcontenttype(iVar1,DAT_0012c3d0);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0012c3d4,uVar6);
    uVar6 = json_object_new_string(DAT_0012c3d8);
    json_object_object_add(uVar7,DAT_0012c3dc,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0012c3e0,uVar6);
    json_object_put(uVar7);
    goto LAB_0012bfd4;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012c3bc);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012c3c0,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0012c3c0,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012c3c4), iVar4 != 0))
    goto LAB_0012bf24;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_0012c3e8);
    pcVar5 = getenv(DAT_0012c3ec);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_0012c3f0),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    uStack_10135 = 0;
    memset(&uStack_10134,0,0x100);
    iVar9 = json_object_object_get_rest(iVar8,DAT_0012c3f4);
    if (iVar9 == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar8,DAT_0012c3f4);
      uVar7 = json_object_get_int();
    }
    iVar9 = json_object_object_get_rest(iVar8,DAT_0012c3f8);
    if (iVar9 != 0) {
      json_object_object_get_rest(iVar8,DAT_0012c3f8);
      iVar9 = json_object_get_int();
      if (iVar9 == 2) {
        uStack_10134 = *DAT_0012c418;
        uStack_10130 = DAT_0012c418[1];
        uStack_1012c = DAT_0012c418[2];
        uStack_10128 = DAT_0012c418[3];
        uStack_10124 = DAT_0012c418[4];
        uStack_10120 = DAT_0012c418[5];
        uStack_1011c = DAT_0012c418[6];
        uStack_10118 = (undefined2)DAT_0012c418[7];
        system((char *)&uStack_10134);
        memcpy(&uStack_10134,DAT_0012c41c,0xd2);
        system((char *)&uStack_10134);
        unlink(DAT_0012c420);
      }
    }
    CMD_Exit_FW_Update_mode(auStack_10034,uVar7);
    iVar9 = FCGI_fopen(DAT_0012c400,DAT_0012c3fc);
    if (iVar9 != 0) {
      FCGI_fwrite(&uStack_10135,1);
      FCGI_fclose(iVar9);
    }
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(0);
      json_object_object_add(iVar4,DAT_0012c3d4,uVar7);
      qcgires_setcontenttype(iVar1,DAT_0012c3d0);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0012c3e0,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0012c3f0);
        goto LAB_0012c1f4;
      }
    }
    else {
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 == (char *)0x0) {
        iVar8 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012c404,0x20);
        json_object_object_add(iVar8,DAT_0012c3dc,uVar7);
        uVar7 = json_object_new_int(DAT_0012c408);
        json_object_object_add(iVar8,DAT_0012c40c,uVar7);
        FCGI_printf(DAT_0012c414,DAT_0012c410);
        qcgires_setcontenttype(iVar1,DAT_0012c3d0);
        uVar7 = json_object_to_json_string(iVar8);
        FCGI_printf(DAT_0012c3e0,uVar7);
      }
      else {
        strcasecmp(pcVar2,DAT_0012c3f0);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_0012c404,0x20);
        json_object_object_add(iVar4,DAT_0012c3dc,uVar7);
        uVar7 = json_object_new_int(DAT_0012c408);
        json_object_object_add(iVar4,DAT_0012c40c,uVar7);
        FCGI_printf(DAT_0012c414,DAT_0012c410);
        qcgires_setcontenttype(iVar1,DAT_0012c3d0);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0012c3e0,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_0012c3f0);
      }
LAB_0012c1f4:
      if (iVar8 != 0) {
        json_object_put(iVar8);
      }
    }
  }
  else {
LAB_0012bf24:
    FCGI_printf(DAT_0012c3c8);
    FCGI_printf(DAT_0012c3cc);
    qcgires_setcontenttype(iVar1,DAT_0012c3d0);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_0012c3d4,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_0012c3c4);
    uVar7 = DAT_0012c3d8;
    if (iVar4 == 1) {
      uVar7 = DAT_0012c3e4;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_0012c3dc,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_0012c3e0,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_0012bfd4:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

