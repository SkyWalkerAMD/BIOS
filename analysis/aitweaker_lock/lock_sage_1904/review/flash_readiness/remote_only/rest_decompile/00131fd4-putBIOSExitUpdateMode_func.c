
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
  undefined1 uStack_100b5;
  undefined4 uStack_100b4;
  undefined4 uStack_100b0;
  undefined4 uStack_100ac;
  undefined4 uStack_100a8;
  undefined4 uStack_100a4;
  undefined4 uStack_100a0;
  undefined4 uStack_1009c;
  undefined2 uStack_10098;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv(DAT_00132534);
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf(DAT_00132544);
    FCGI_printf(DAT_00132548);
    qcgires_setcontenttype(iVar1,DAT_0013254c);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_00132550,uVar6);
    uVar6 = json_object_new_string(DAT_00132554);
    json_object_object_add(uVar7,DAT_00132558,uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf(DAT_0013255c,uVar6);
    json_object_put(uVar7);
    goto LAB_00132150;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00132538);
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0013253c,0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_0013253c,0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00132540), iVar4 != 0))
    goto LAB_001320a0;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar8 = json_object_new_object();
    pcVar2 = getenv(DAT_00132564);
    pcVar5 = getenv(DAT_00132568);
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,DAT_0013256c),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    uStack_100b5 = 0;
    memset(&uStack_100b4,0,0x80);
    iVar9 = json_object_object_get_rest(iVar8,DAT_00132570);
    if (iVar9 == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar8,DAT_00132570);
      uVar7 = json_object_get_int64();
    }
    iVar9 = json_object_object_get_rest(iVar8,DAT_00132574);
    if (iVar9 != 0) {
      json_object_object_get_rest(iVar8,DAT_00132574);
      iVar9 = json_object_get_int64();
      if (iVar9 == 2) {
        uStack_100b4 = *DAT_00132594;
        uStack_100b0 = DAT_00132594[1];
        uStack_100ac = DAT_00132594[2];
        uStack_100a8 = DAT_00132594[3];
        uStack_100a4 = DAT_00132594[4];
        uStack_100a0 = DAT_00132594[5];
        uStack_1009c = DAT_00132594[6];
        uStack_10098 = (undefined2)DAT_00132594[7];
        system((char *)&uStack_100b4);
        sprintf((char *)&uStack_100b4,DAT_00132598,0xf);
        system((char *)&uStack_100b4);
        unlink(DAT_0013259c);
      }
    }
    CMD_Exit_FW_Update_mode(auStack_10034,uVar7);
    iVar9 = FCGI_fopen(DAT_0013257c,DAT_00132578);
    if (iVar9 != 0) {
      FCGI_fwrite(&uStack_100b5,1);
      FCGI_fclose(iVar9);
    }
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(0);
      json_object_object_add(iVar4,DAT_00132550,uVar7);
      qcgires_setcontenttype(iVar1,DAT_0013254c);
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf(DAT_0013255c,uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,DAT_0013256c);
        goto LAB_00132370;
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
        uVar7 = json_object_new_string_len(DAT_00132580,0x20);
        json_object_object_add(iVar8,DAT_00132558,uVar7);
        uVar7 = json_object_new_int(DAT_00132584);
        json_object_object_add(iVar8,DAT_00132588,uVar7);
        FCGI_printf(DAT_00132590,DAT_0013258c);
        qcgires_setcontenttype(iVar1,DAT_0013254c);
        uVar7 = json_object_to_json_string(iVar8);
        FCGI_printf(DAT_0013255c,uVar7);
      }
      else {
        strcasecmp(pcVar2,DAT_0013256c);
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len(DAT_00132580,0x20);
        json_object_object_add(iVar4,DAT_00132558,uVar7);
        uVar7 = json_object_new_int(DAT_00132584);
        json_object_object_add(iVar4,DAT_00132588,uVar7);
        FCGI_printf(DAT_00132590,DAT_0013258c);
        qcgires_setcontenttype(iVar1,DAT_0013254c);
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf(DAT_0013255c,uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,DAT_0013256c);
      }
LAB_00132370:
      if (iVar8 != 0) {
        json_object_put(iVar8);
      }
    }
  }
  else {
LAB_001320a0:
    FCGI_printf(DAT_00132544);
    FCGI_printf(DAT_00132548);
    qcgires_setcontenttype(iVar1,DAT_0013254c);
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,DAT_00132550,uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_00132540);
    uVar7 = DAT_00132554;
    if (iVar4 == 1) {
      uVar7 = DAT_00132560;
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,DAT_00132558,uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf(DAT_0013255c,uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_00132150:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

