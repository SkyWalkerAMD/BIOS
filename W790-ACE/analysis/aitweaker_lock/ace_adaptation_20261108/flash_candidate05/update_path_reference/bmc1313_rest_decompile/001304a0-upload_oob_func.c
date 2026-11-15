
void upload_oob_func(void)

{
  char *pcVar1;
  int iVar2;
  ulong uVar3;
  int iVar4;
  int iVar5;
  char *__s1;
  char *__s;
  size_t __n;
  undefined4 uVar6;
  undefined4 uVar7;
  char acStack_58 [64];
  
  pcVar1 = getenv(DAT_00130864);
  iVar2 = qcgireq_setoption(0,1,DAT_00130868);
  if ((pcVar1 == (char *)0x0) || (uVar3 = strtoul(pcVar1,(char **)0x0,10), uVar3 == 0)) {
    FCGI_printf(DAT_001308a4);
    qcgires_setcontenttype(iVar2,DAT_00130888);
    uVar7 = json_object_new_object();
    uVar6 = 5;
LAB_00130770:
    uVar6 = json_object_new_int(uVar6);
    json_object_object_add(uVar7,DAT_0013088c,uVar6);
    uVar6 = DAT_001308a8;
  }
  else {
    if (0x4300000 < uVar3) {
      FCGI_printf(DAT_001308ac);
      qcgires_setcontenttype(iVar2,DAT_00130888);
      uVar7 = json_object_new_object();
      uVar6 = 6;
      goto LAB_00130770;
    }
    if (iVar2 == 0) {
      qcgires_error(0,DAT_001308b4);
    }
    iVar2 = qcgireq_parse(iVar2,0);
    pre_call_hook();
    iVar4 = qcgisess_init(iVar2,0);
    if (iVar4 != 0) {
      pcVar1 = getenv(DAT_0013086c);
      iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00130870);
      if (iVar5 == 1 && pcVar1 != (char *)0x0) {
        __s1 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00130874,0);
        __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00130874,0);
        __n = strlen(__s);
        iVar5 = strncmp(__s1,pcVar1,__n);
        if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00130878), iVar5 != 0))
        goto LAB_00130684;
        pre_authorized_call_hook(iVar2,iVar4);
        uVar6 = json_object_new_object();
        memset(acStack_58,0,0x40);
        pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_0013087c,0);
        uVar7 = (**(code **)(iVar2 + 0x18))(iVar2,DAT_00130880,0);
        snprintf(acStack_58,0x40,DAT_00130884,uVar7);
        iVar5 = rename(pcVar1,acStack_58);
        if (iVar5 == -1) {
          FCGI_fprintf(DAT_001308c0,DAT_001308b8,DAT_001308bc);
          qcgires_setcontenttype(iVar2,DAT_00130888);
LAB_00130858:
          FCGI_printf(DAT_001308c4);
        }
        else {
          qcgires_setcontenttype(iVar2,DAT_00130888);
          if (iVar5 != 0) goto LAB_00130858;
        }
        uVar7 = json_object_new_int(iVar5);
        json_object_object_add(uVar6,DAT_0013088c,uVar7);
        uVar7 = json_object_to_json_string(uVar6);
        FCGI_printf(DAT_00130890,uVar7);
        json_object_put(uVar6);
      }
      else {
LAB_00130684:
        FCGI_printf(DAT_00130894);
        FCGI_printf(DAT_00130898);
        qcgires_setcontenttype(iVar2,DAT_00130888);
        uVar7 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar7,DAT_0013088c,uVar6);
        iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00130878);
        uVar6 = DAT_0013089c;
        if (iVar5 == 1) {
          uVar6 = DAT_001308b0;
        }
        uVar6 = json_object_new_string(uVar6);
        json_object_object_add(uVar7,DAT_001308a0,uVar6);
        uVar6 = json_object_to_json_string(uVar7);
        FCGI_printf(DAT_00130890,uVar6);
        json_object_put(uVar7);
        qcgisess_clear(iVar4);
      }
      post_authorized_call_hook(iVar2,iVar4);
      qcgisess_save(iVar4);
      (**(code **)(iVar4 + 0x58))(iVar4);
      goto LAB_00130734;
    }
    FCGI_printf(DAT_00130894);
    FCGI_printf(DAT_00130898);
    qcgires_setcontenttype(iVar2,DAT_00130888);
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,DAT_0013088c,uVar6);
    uVar6 = DAT_0013089c;
  }
  uVar6 = json_object_new_string(uVar6);
  json_object_object_add(uVar7,DAT_001308a0,uVar6);
  uVar6 = json_object_to_json_string(uVar7);
  FCGI_printf(DAT_00130890,uVar6);
  json_object_put(uVar7);
LAB_00130734:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

