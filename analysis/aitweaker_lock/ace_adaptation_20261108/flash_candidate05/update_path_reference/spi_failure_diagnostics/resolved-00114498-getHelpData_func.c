
void getHelpData_func(void)

{
  undefined4 *puVar1;
  undefined1 uVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  size_t sVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  void *__ptr;
  int iVar12;
  int iVar13;
  undefined4 uVar14;
  undefined4 *puVar15;
  undefined1 *local_b4;
  undefined1 auStack_ac [44];
  stat sStack_80;
  
  iVar3 = qcgireq_parse(0);
  pcVar4 = getenv("HTTP_X_CSRFTOKEN");
  pre_call_hook(iVar3);
  iVar5 = qcgisess_init(iVar3,0);
  if (iVar5 == 0) {
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar3,"application/json");
    uVar11 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar11,"cc",uVar10);
    uVar10 = json_object_new_string("Invalid Authentication");
    json_object_object_add(uVar11,"error",uVar10);
    uVar10 = json_object_to_json_string(uVar11);
    FCGI_printf("%s",uVar10);
    json_object_put(uVar11);
    goto LAB_00114610;
  }
  iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,"authorized");
  if (iVar6 == 1 && pcVar4 != (char *)0x0) {
    pcVar7 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,"CSRFTOKEN",0);
    pcVar8 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,"CSRFTOKEN",0);
    sVar9 = strlen(pcVar8);
    iVar6 = strncmp(pcVar7,pcVar4,sVar9);
    if ((iVar6 != 0) || (iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,"passwordStatus"), iVar6 != 0))
    goto LAB_00114560;
    pre_authorized_call_hook(iVar3,iVar5);
    iVar6 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    iVar12 = json_object_new_object();
    pcVar4 = getenv("REQUEST_METHOD");
    pcVar7 = getenv("CONTENT_TYPE");
    if ((pcVar4 != (char *)0x0) &&
       (iVar13 = strcasecmp(pcVar4,"GET"),
       iVar13 != 0 && (pcVar7 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(iVar12);
      iVar12 = json_tokener_parse(__ptr);
    }
    if (*0x16dbac == 0) {
LAB_00114714:
      local_b4 = auStack_ac;
      pcVar7 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,"file",0);
      iVar13 = isValidFilename();
      if (iVar13 == 0) {
        sVar9 = strlen(pcVar7);
        pcVar8 = malloc(sVar9 + 0x18);
        puVar1 = "/usr/local/www/res/oem/";
        if (pcVar8 != (char *)0x0) {
          uVar11 = "/usr/local/www/res/oem/"[1];
          uVar10 = "/usr/local/www/res/oem/"[2];
          uVar14 = "/usr/local/www/res/oem/"[3];
          puVar15 = "/usr/local/www/res/oem/" + 4;
          *(undefined4 *)pcVar8 = *"/usr/local/www/res/oem/";
          *(undefined4 *)(pcVar8 + 4) = uVar11;
          *(undefined4 *)(pcVar8 + 8) = uVar10;
          *(undefined4 *)(pcVar8 + 0xc) = uVar14;
          uVar11 = puVar1[5];
          *(undefined4 *)(pcVar8 + 0x10) = *puVar15;
          *(undefined4 *)(pcVar8 + 0x14) = uVar11;
          strcpy(pcVar8 + 0x17,pcVar7);
          iVar13 = __xstat(3,pcVar8,&sStack_80);
          if (iVar13 < 0) {
            free(pcVar8);
            IDBG_LINUXAPP_DbgOut(0x82,"[%s:%d]Unable to fetch the file information\n","video_log.c",0xf1);
            goto LAB_0011489c;
          }
        }
        FCGI_printf("content-disposition: attachment\r\n");
        FCGI_printf("X-Sendfile2: %s 0-\r\n\r\n",pcVar8);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          IPMI_lo_Logout(local_b4);
          if (iVar6 != 0) {
            json_object_put(iVar6);
          }
          goto LAB_001145f0;
        }
        strcasecmp(pcVar4,"GET");
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
        IPMI_lo_Logout(local_b4);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        strcasecmp(pcVar4,"GET");
      }
      else {
LAB_0011489c:
        IPMI_lo_Logout(local_b4);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          iVar6 = json_object_new_object();
          uVar11 = json_object_new_string_len("404 Not Found",0xd);
          json_object_object_add(iVar6,"error",uVar11);
          uVar11 = json_object_new_int(1);
          json_object_object_add(iVar6,"code",uVar11);
          uVar11 = "404 Not Found";
          goto LAB_001149c0;
        }
        strcasecmp(pcVar4,"GET");
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
        iVar6 = json_object_new_object();
        uVar11 = json_object_new_string_len("404 Not Found",0xd);
        json_object_object_add(iVar6,"error",uVar11);
        uVar11 = json_object_new_int(1);
        json_object_object_add(iVar6,"code",uVar11);
        uVar11 = "404 Not Found";
LAB_00114928:
        FCGI_printf("Status: %s \n",uVar11);
        qcgires_setcontenttype(iVar3,"application/json");
        uVar11 = json_object_to_json_string(iVar6);
        FCGI_printf("%s",uVar11);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        strcasecmp(pcVar4,"GET");
      }
      if (iVar12 != 0) {
        json_object_put(iVar12);
      }
    }
    else {
      uVar2 = (**(code **)(iVar5 + 0x24))(iVar5,"role");
      iVar13 = IPMI_lo_Login(0x14bd0c,0x14bd0c,auStack_ac,uVar2,1,0,0,0);
      if (iVar13 == 0) goto LAB_00114714;
      IPMI_lo_Logout(auStack_ac);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar4 != (char *)0x0) {
        strcasecmp(pcVar4,"GET");
        if (iVar12 != 0) {
          json_object_put(iVar12);
        }
        iVar6 = json_object_new_object();
        uVar11 = json_object_new_string_len("Session could not be established",0x20);
        json_object_object_add(iVar6,"error",uVar11);
        uVar11 = json_object_new_int(0x517);
        json_object_object_add(iVar6,"code",uVar11);
        uVar11 = "401 Unauthorized";
        goto LAB_00114928;
      }
      iVar6 = json_object_new_object();
      uVar11 = json_object_new_string_len("Session could not be established",0x20);
      json_object_object_add(iVar6,"error",uVar11);
      uVar11 = json_object_new_int(0x517);
      json_object_object_add(iVar6,"code",uVar11);
      uVar11 = "401 Unauthorized";
LAB_001149c0:
      FCGI_printf("Status: %s \n",uVar11);
      qcgires_setcontenttype(iVar3,"application/json");
      uVar11 = json_object_to_json_string(iVar6);
      FCGI_printf("%s",uVar11);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
    }
  }
  else {
LAB_00114560:
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar3,"application/json");
    uVar10 = json_object_new_object();
    uVar11 = json_object_new_int(7);
    json_object_object_add(uVar10,"cc",uVar11);
    iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,"passwordStatus");
    uVar11 = "Invalid Authentication";
    if (iVar6 == 1) {
      uVar11 = "Password should be changed for default user and should have a minimum of 8 characters.";
    }
    uVar11 = json_object_new_string(uVar11);
    json_object_object_add(uVar10,"error",uVar11);
    uVar11 = json_object_to_json_string(uVar10);
    FCGI_printf("%s",uVar11);
    json_object_put(uVar10);
    qcgisess_clear(iVar5);
  }
LAB_001145f0:
  post_authorized_call_hook(iVar3,iVar5);
  qcgisess_save(iVar5);
  (**(code **)(iVar5 + 0x58))(iVar5);
LAB_00114610:
  post_call_hook(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
  return;
}

