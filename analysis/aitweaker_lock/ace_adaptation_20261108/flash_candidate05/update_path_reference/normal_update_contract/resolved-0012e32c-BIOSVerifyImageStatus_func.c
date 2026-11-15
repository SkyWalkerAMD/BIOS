

void BIOSVerifyImageStatus_func(void)

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
  uint uVar10;
  undefined4 uStack_10044;
  char acStack_10040 [12];
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar1 = qcgireq_parse(0);
  pcVar2 = getenv("HTTP_X_CSRFTOKEN");
  pre_call_hook(iVar1);
  iVar3 = qcgisess_init(iVar1,0);
  if (iVar3 == 0) {
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar1,"application/json");
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,"cc",uVar6);
    uVar6 = json_object_new_string("Invalid Authentication");
    json_object_object_add(uVar7,"error",uVar6);
    uVar6 = json_object_to_json_string(uVar7);
    FCGI_printf("%s",uVar6);
    json_object_put(uVar7);
    goto LAB_0012e4a8;
  }
  iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,"authorized");
  if (iVar4 == 1 && pcVar2 != (char *)0x0) {
    pcVar5 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,"CSRFTOKEN",0);
    __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,"CSRFTOKEN",0);
    __n = strlen(__s);
    iVar4 = strncmp(pcVar5,pcVar2,__n);
    if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,"passwordStatus"), iVar4 != 0))
    goto LAB_0012e3f8;
    pre_authorized_call_hook(iVar1,iVar3);
    iVar4 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar8 = json_object_new_object();
    pcVar2 = getenv("REQUEST_METHOD");
    pcVar5 = getenv("CONTENT_TYPE");
    if ((pcVar2 != (char *)0x0) &&
       (iVar9 = strcasecmp(pcVar2,"GET"),
       iVar9 != 0 && (__ptr != (void *)0x0 && pcVar5 != (char *)0x0))) {
      json_object_put(iVar8);
      iVar8 = json_tokener_parse(__ptr);
    }
    pcVar5 = (char *)(**(code **)(iVar1 + 0x18))(iVar1,"COMPONENT_ID",0);
    snprintf(acStack_10040,10,"%s",pcVar5);
    uVar10 = strtol(pcVar5,(char **)0x0,10);
    uVar10 = uVar10 & 0xff;
    CMD_Get_Firmware_Progress(auStack_10034,uVar10,2,&uStack_10044,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,"COMPONENT_ID",uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,"PROGRESS",uVar7);
      qcgires_setcontenttype(iVar1,"application/json");
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf("%s",uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,"GET");
LAB_0012e730:
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
      }
    }
    else {
      uVar7 = json_object_new_int(uVar10);
      json_object_object_add(iVar4,"COMPONENT_ID",uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar4,"PROGRESS",uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar2 != (char *)0x0) {
        strcasecmp(pcVar2,"GET");
        if (iVar8 != 0) {
          json_object_put(iVar8);
        }
        iVar4 = json_object_new_object();
        uVar7 = json_object_new_string_len("Error in Finish Firmware Upload",0x1f);
        json_object_object_add(iVar4,"error",uVar7);
        uVar7 = json_object_new_int(0x55d);
        json_object_object_add(iVar4,"code",uVar7);
        FCGI_printf("Status: %s \n","500 Internal Server Error");
        qcgires_setcontenttype(iVar1,"application/json");
        uVar7 = json_object_to_json_string(iVar4);
        FCGI_printf("%s",uVar7);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        strcasecmp(pcVar2,"GET");
        goto LAB_0012e730;
      }
      iVar4 = json_object_new_object();
      uVar7 = json_object_new_string_len("Error in Finish Firmware Upload",0x1f);
      json_object_object_add(iVar4,"error",uVar7);
      uVar7 = json_object_new_int(0x55d);
      json_object_object_add(iVar4,"code",uVar7);
      FCGI_printf("Status: %s \n","500 Internal Server Error");
      qcgires_setcontenttype(iVar1,"application/json");
      uVar7 = json_object_to_json_string(iVar4);
      FCGI_printf("%s",uVar7);
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
  else {
LAB_0012e3f8:
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar1,"application/json");
    uVar6 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar6,"cc",uVar7);
    iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,"passwordStatus");
    uVar7 = "Invalid Authentication";
    if (iVar4 == 1) {
      uVar7 = "Password should be changed for default user and should have a minimum of 8 characters.";
    }
    uVar7 = json_object_new_string(uVar7);
    json_object_object_add(uVar6,"error",uVar7);
    uVar7 = json_object_to_json_string(uVar6);
    FCGI_printf("%s",uVar7);
    json_object_put(uVar6);
    qcgisess_clear(iVar3);
  }
  post_authorized_call_hook(iVar1,iVar3);
  qcgisess_save(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
LAB_0012e4a8:
  post_call_hook(iVar1);
  (**(code **)(iVar1 + 0x58))(iVar1);
  return;
}

