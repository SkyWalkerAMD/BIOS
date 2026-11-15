

void uploadBIOSFWImage_func(void)

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
  
  pcVar1 = getenv("CONTENT_LENGTH");
  iVar2 = qcgireq_setoption(0,1,"/var/");
  if ((pcVar1 == (char *)0x0) || (uVar3 = strtoul(pcVar1,(char **)0x0,10), uVar3 == 0)) {
    FCGI_printf("Status: 411 Length Required \r\n");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar7 = json_object_new_object();
    uVar6 = 5;
LAB_0012ff70:
    uVar6 = json_object_new_int(uVar6);
    json_object_object_add(uVar7,"cc",uVar6);
    uVar6 = "Invalid Content Length received";
  }
  else {
    if (0x4300000 < uVar3) {
      FCGI_printf("Status: 413 Request Entity Too Large \r\n");
      qcgires_setcontenttype(iVar2,"application/json");
      uVar7 = json_object_new_object();
      uVar6 = 6;
      goto LAB_0012ff70;
    }
    if (iVar2 == 0) {
      qcgires_error(0,"Can't set options.");
    }
    iVar2 = qcgireq_parse(iVar2,0);
    pre_call_hook();
    iVar4 = qcgisess_init(iVar2,0);
    if (iVar4 != 0) {
      pcVar1 = getenv("HTTP_X_CSRFTOKEN");
      iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"authorized");
      if (iVar5 == 1 && pcVar1 != (char *)0x0) {
        __s1 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,"CSRFTOKEN",0);
        __s = (char *)(**(code **)(iVar4 + 0x18))(iVar4,"CSRFTOKEN",0);
        __n = strlen(__s);
        iVar5 = strncmp(__s1,pcVar1,__n);
        if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"passwordStatus"), iVar5 != 0))
        goto LAB_0012fe88;
        pre_authorized_call_hook(iVar2,iVar4);
        uVar6 = json_object_new_object();
        pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,"hpmbios.savepath",0);
        iVar5 = rename(pcVar1,"/var/bios.bin");
        if (iVar5 == -1) {
          FCGI_fprintf(0x175928,"\n-------------------------->%s\n","Temp Move Failed");
          qcgires_setcontenttype(iVar2,"application/json");
LAB_00130058:
          FCGI_printf("status: 500 (Internal Server Error) \n");
        }
        else {
          qcgires_setcontenttype(iVar2,"application/json");
          if (iVar5 != 0) goto LAB_00130058;
        }
        uVar7 = json_object_new_int(iVar5);
        json_object_object_add(uVar6,"cc",uVar7);
        uVar7 = json_object_to_json_string(uVar6);
        FCGI_printf("%s",uVar7);
        json_object_put(uVar6);
      }
      else {
LAB_0012fe88:
        FCGI_printf("Status: 401 Unauthorized \n");
        FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
        qcgires_setcontenttype(iVar2,"application/json");
        uVar7 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar7,"cc",uVar6);
        iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"passwordStatus");
        uVar6 = "Invalid Authentication";
        if (iVar5 == 1) {
          uVar6 = "Password should be changed for default user and should have a minimum of 8 characters.";
        }
        uVar6 = json_object_new_string(uVar6);
        json_object_object_add(uVar7,"error",uVar6);
        uVar6 = json_object_to_json_string(uVar7);
        FCGI_printf("%s",uVar6);
        json_object_put(uVar7);
        qcgisess_clear(iVar4);
      }
      post_authorized_call_hook(iVar2,iVar4);
      qcgisess_save(iVar4);
      (**(code **)(iVar4 + 0x58))(iVar4);
      goto LAB_0012ff38;
    }
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar7 = json_object_new_object();
    uVar6 = json_object_new_int(7);
    json_object_object_add(uVar7,"cc",uVar6);
    uVar6 = "Invalid Authentication";
  }
  uVar6 = json_object_new_string(uVar6);
  json_object_object_add(uVar7,"error",uVar6);
  uVar6 = json_object_to_json_string(uVar7);
  FCGI_printf("%s",uVar6);
  json_object_put(uVar7);
LAB_0012ff38:
  post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x0012ff4c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

