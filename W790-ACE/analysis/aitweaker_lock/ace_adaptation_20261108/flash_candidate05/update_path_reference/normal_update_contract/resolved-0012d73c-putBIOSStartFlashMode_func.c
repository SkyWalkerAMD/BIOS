

void putBIOSStartFlashMode_func(void)

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
  undefined4 uStack_10044;
  undefined4 uStack_10040;
  undefined1 auStack_10034 [4];
  int iStack_10030;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv("HTTP_X_CSRFTOKEN");
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar8 = json_object_new_object();
    uVar7 = json_object_new_int(7);
    json_object_object_add(uVar8,"cc",uVar7);
    uVar7 = json_object_new_string("Invalid Authentication");
    json_object_object_add(uVar8,"error",uVar7);
    uVar7 = json_object_to_json_string(uVar8);
    FCGI_printf("%s",uVar7);
    json_object_put(uVar8);
    goto LAB_0012d8b8;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"authorized");
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,"CSRFTOKEN",0);
    __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,"CSRFTOKEN",0);
    __n = strlen(__s);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"passwordStatus"), iVar5 != 0))
    goto LAB_0012d808;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar9 = json_object_new_object();
    pcVar3 = getenv("REQUEST_METHOD");
    pcVar6 = getenv("CONTENT_TYPE");
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,"GET"),
       iVar10 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(iVar9);
      iVar9 = json_tokener_parse(__ptr);
    }
    iVar10 = json_object_object_get_rest(iVar9,"COMPONENT_ID");
    if (iVar10 == 0) {
      uVar1 = 0xff;
    }
    else {
      json_object_object_get_rest(iVar9,"COMPONENT_ID");
      uVar1 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,"COMPONENT_DATA_LEN");
    if (iVar10 == 0) {
      uStack_10044 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,"COMPONENT_DATA_LEN");
      uStack_10044 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,"FWUPDATEID");
    if (iVar10 == 0) {
      uVar8 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,"FWUPDATEID");
      uVar8 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,"SECTION_FLASH");
    if (iVar10 == 0) {
      uStack_10040 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,"SECTION_FLASH");
      uStack_10040 = json_object_get_int();
    }
    iVar10 = json_object_object_get_rest(iVar9,"FlashOffset");
    if (iVar10 == 0) {
      uVar7 = 0xffffffff;
    }
    else {
      json_object_object_get_rest(iVar9,"FlashOffset");
      uVar7 = json_object_get_int();
    }
    CMD_Start_Firmware_Update(auStack_10034,uVar8,uVar1,uVar7,uStack_10044,uStack_10040,1);
    if (iStack_10030 == 0) {
      uVar7 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,"COMPONENT_ID",uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,"COMPONENT_DATA_LEN",uVar7);
      uVar8 = json_object_new_int(uVar8);
      json_object_object_add(iVar5,"FWUPDATEID",uVar8);
      qcgires_setcontenttype(iVar2,"application/json");
      uVar8 = json_object_to_json_string(iVar5);
      FCGI_printf("%s",uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,"GET");
        goto LAB_0012dc28;
      }
    }
    else {
      uVar7 = json_object_new_int(uVar1);
      json_object_object_add(iVar5,"COMPONENT_ID",uVar7);
      uVar7 = json_object_new_int(uStack_10044);
      json_object_object_add(iVar5,"COMPONENT_DATA_LEN",uVar7);
      uVar8 = json_object_new_int(uVar8);
      json_object_object_add(iVar5,"FWUPDATEID",uVar8);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        iVar9 = json_object_new_object();
        uVar8 = json_object_new_string_len("Error in Finish Firmware Upload",0x1f);
        json_object_object_add(iVar9,"error",uVar8);
        uVar8 = json_object_new_int(0x55d);
        json_object_object_add(iVar9,"code",uVar8);
        FCGI_printf("Status: %s \n","500 Internal Server Error");
        qcgires_setcontenttype(iVar2,"application/json");
        uVar8 = json_object_to_json_string(iVar9);
        FCGI_printf("%s",uVar8);
      }
      else {
        strcasecmp(pcVar3,"GET");
        if (iVar9 != 0) {
          json_object_put(iVar9);
        }
        iVar5 = json_object_new_object();
        uVar8 = json_object_new_string_len("Error in Finish Firmware Upload",0x1f);
        json_object_object_add(iVar5,"error",uVar8);
        uVar8 = json_object_new_int(0x55d);
        json_object_object_add(iVar5,"code",uVar8);
        FCGI_printf("Status: %s \n","500 Internal Server Error");
        qcgires_setcontenttype(iVar2,"application/json");
        uVar8 = json_object_to_json_string(iVar5);
        FCGI_printf("%s",uVar8);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,"GET");
      }
LAB_0012dc28:
      if (iVar9 != 0) {
        json_object_put(iVar9);
      }
    }
  }
  else {
LAB_0012d808:
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar7 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar7,"cc",uVar8);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"passwordStatus");
    uVar8 = "Invalid Authentication";
    if (iVar5 == 1) {
      uVar8 = "Password should be changed for default user and should have a minimum of 8 characters.";
    }
    uVar8 = json_object_new_string(uVar8);
    json_object_object_add(uVar7,"error",uVar8);
    uVar8 = json_object_to_json_string(uVar7);
    FCGI_printf("%s",uVar8);
    json_object_put(uVar7);
    qcgisess_clear(iVar4);
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0012d8b8:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x0012d8d4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

