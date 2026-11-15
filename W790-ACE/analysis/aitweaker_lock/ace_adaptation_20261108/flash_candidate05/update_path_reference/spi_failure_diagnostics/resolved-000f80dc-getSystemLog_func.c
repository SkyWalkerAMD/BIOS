
void getSystemLog_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t sVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  void *__ptr;
  char *pcVar11;
  undefined4 uVar12;
  char *__s;
  int iVar13;
  undefined4 *puVar14;
  int local_bc;
  undefined1 *local_b4;
  char *local_a8;
  char *local_a4;
  undefined4 local_a0;
  undefined4 uStack_9c;
  undefined4 uStack_98;
  undefined4 uStack_94;
  undefined4 local_90;
  undefined2 local_8c;
  undefined2 local_8a;
  undefined2 local_88;
  undefined2 local_86;
  undefined2 local_84;
  undefined2 local_82;
  undefined1 auStack_80 [44];
  tm tStack_54;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv("HTTP_X_CSRFTOKEN");
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar10 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar10,"cc",uVar9);
    uVar9 = json_object_new_string("Invalid Authentication");
    json_object_object_add(uVar10,"error",uVar9);
    uVar9 = json_object_to_json_string(uVar10);
    FCGI_printf("%s",uVar9);
    json_object_put(uVar10);
    goto LAB_000f8254;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"authorized");
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_000f81a4:
    FCGI_printf("Status: 401 Unauthorized \n");
    FCGI_printf("Set-Cookie: QSESSIONID=; path=/; secure;HttpOnly;Samesite=Lax\n");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar9 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar9,"cc",uVar10);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"passwordStatus");
    uVar10 = "Invalid Authentication";
    if (iVar5 == 1) {
      uVar10 = "Password should be changed for default user and should have a minimum of 8 characters.";
    }
    uVar10 = json_object_new_string(uVar10);
    json_object_object_add(uVar9,"error",uVar10);
    uVar10 = json_object_to_json_string(uVar9);
    FCGI_printf("%s",uVar10);
    json_object_put(uVar9);
    qcgisess_clear(iVar4);
    goto LAB_000f8234;
  }
  pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,"CSRFTOKEN",0);
  pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,"CSRFTOKEN",0);
  sVar8 = strlen(pcVar7);
  iVar5 = strncmp(pcVar6,pcVar3,sVar8);
  if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,"passwordStatus"), iVar5 != 0))
  goto LAB_000f81a4;
  pre_authorized_call_hook(iVar2,iVar4);
  uVar10 = json_object_new_array();
  __ptr = (void *)qcgireq_getquery(4);
  local_bc = json_object_new_object();
  pcVar3 = getenv("REQUEST_METHOD");
  pcVar6 = getenv("CONTENT_TYPE");
  if ((pcVar3 != (char *)0x0) &&
     (iVar5 = strcasecmp(pcVar3,"GET"),
     iVar5 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
    json_object_put(local_bc);
    local_bc = json_tokener_parse(__ptr);
  }
  if (*0x16dbac != 0) {
    uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,"role");
    iVar5 = IPMI_lo_Login(0x14bd0c,0x14bd0c,auStack_80,uVar1,1,0,0,0);
    if (iVar5 == 0) goto LAB_000f8364;
    IPMI_lo_Logout(auStack_80);
    iVar13 = json_object_array_length(uVar10);
    iVar5 = 0;
    if (0 < iVar13) {
      do {
        json_object_array_get_idx(uVar10,iVar5);
        iVar5 = iVar5 + 1;
        json_object_put();
      } while (iVar13 != iVar5);
    }
    json_object_put(uVar10);
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (pcVar3 == (char *)0x0) {
      iVar5 = json_object_new_object();
      uVar10 = json_object_new_string_len("Session could not be established",0x20);
      json_object_object_add(iVar5,"error",uVar10);
      uVar10 = json_object_new_int(0x517);
      json_object_object_add(iVar5,"code",uVar10);
      FCGI_printf("Status: %s \n","401 Unauthorized");
      qcgires_setcontenttype(iVar2,"application/json");
      uVar10 = json_object_to_json_string(iVar5);
      FCGI_printf("%s",uVar10);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      goto LAB_000f8234;
    }
    iVar5 = strcasecmp(pcVar3,"GET");
    if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
       (iVar5 = strcasecmp(pcVar3,"PUT"), iVar5 == 0)) {
      strncasecmp(pcVar6,"application/json",0x10);
    }
    if (local_bc != 0) {
      json_object_put(local_bc);
    }
    iVar5 = json_object_new_object();
    uVar10 = json_object_new_string_len("Session could not be established",0x20);
    json_object_object_add(iVar5,"error",uVar10);
    uVar10 = json_object_new_int(0x517);
    json_object_object_add(iVar5,"code",uVar10);
    FCGI_printf("Status: %s \n","401 Unauthorized");
    qcgires_setcontenttype(iVar2,"application/json");
    uVar10 = json_object_to_json_string(iVar5);
    FCGI_printf("%s",uVar10);
    if (iVar5 != 0) {
      json_object_put(iVar5);
    }
    strcasecmp(pcVar3,"GET");
    goto LAB_000f85f4;
  }
LAB_000f8364:
  local_b4 = auStack_80;
  local_a8 = (char *)0x0;
  memset(&tStack_54,0,0x2c);
  iVar5 = (**(code **)(iVar2 + 0x24))(iVar2,"level");
  if (iVar5 == 0) {
    local_90 = 0;
    local_8c = 0;
    local_8a = 0;
    local_88 = 0;
    local_86 = 0;
    local_84 = 0;
    local_82 = 0;
switchD_000f869c_caseD_1:
    puVar14 = "/var/log/alert.log";
    goto LAB_000f83bc;
  }
  memset(&local_a0,0,0x20);
  switch(iVar5) {
  default:
    goto switchD_000f869c_caseD_1;
  case 2:
    local_a0 = *"/var/log/crit.log";
    uStack_9c = "/var/log/crit.log"[1];
    uStack_98 = "/var/log/crit.log"[2];
    uStack_94 = "/var/log/crit.log"[3];
    local_90 = CONCAT22(local_90._2_2_,(short)"/var/log/crit.log"[4]);
    break;
  case 3:
    local_a0 = *"/var/log/err.log";
    uStack_9c = "/var/log/err.log"[1];
    uStack_98 = "/var/log/err.log"[2];
    uStack_94 = "/var/log/err.log"[3];
    local_90 = CONCAT31(local_90._1_3_,(char)"/var/log/err.log"[4]);
    break;
  case 4:
    local_a0 = *"/var/log/notice.log";
    uStack_9c = "/var/log/notice.log"[1];
    uStack_98 = "/var/log/notice.log"[2];
    uStack_94 = "/var/log/notice.log"[3];
    local_90 = "/var/log/notice.log"[4];
    break;
  case 5:
    local_a0 = *"/var/log/warning.log";
    uStack_9c = "/var/log/warning.log"[1];
    uStack_98 = "/var/log/warning.log"[2];
    uStack_94 = "/var/log/warning.log"[3];
    local_90 = "/var/log/warning.log"[4];
    local_8c = CONCAT11(local_8c._1_1_,(char)"/var/log/warning.log"[5]);
    break;
  case 6:
    puVar14 = "/var/log/debug.log";
    goto LAB_000f83bc;
  case 7:
    puVar14 = "/var/log/emerg.log";
LAB_000f83bc:
    local_a0 = *puVar14;
    uStack_9c = puVar14[1];
    uStack_98 = puVar14[2];
    uStack_94 = puVar14[3];
    local_90._0_3_ = (undefined3)puVar14[4];
    break;
  case 8:
    local_a0 = *"/var/log/info.log";
    uStack_9c = "/var/log/info.log"[1];
    uStack_98 = "/var/log/info.log"[2];
    uStack_94 = "/var/log/info.log"[3];
    local_90 = CONCAT22(local_90._2_2_,(short)"/var/log/info.log"[4]);
  }
  pcVar6 = (char *)fileread(&local_a0);
  local_a8 = pcVar6;
  if (pcVar6 != (char *)0x0) {
    pcVar11 = strsep(&local_a8,"\n");
    pcVar7 = " ";
    if (pcVar11 != (char *)0x0) {
      iVar5 = 1;
      do {
        uVar9 = json_object_new_object();
        uVar12 = json_object_new_int(iVar5);
        json_object_object_add(uVar9,"id",uVar12);
        strtok_r(pcVar11,pcVar7,&local_a4);
        pcVar11 = strtok_r((char *)0x0,pcVar7,&local_a4);
        __s = strtok_r((char *)0x0,pcVar7,&local_a4);
        iVar5 = iVar5 + 1;
        if ((pcVar11 != (char *)0x0) &&
           (iVar13 = __isoc99_sscanf(pcVar11,"%d-%d-%dT%d:%d:%d.%*d-%*d:%*d",&tStack_54.tm_year,&tStack_54.tm_mon,
                                     &tStack_54.tm_mday,&tStack_54.tm_hour,&tStack_54.tm_min,
                                     &tStack_54), iVar13 == 6)) {
          tStack_54.tm_year = tStack_54.tm_year + -0x76c;
          tStack_54.tm_mon = tStack_54.tm_mon + -1;
          tStack_54.tm_isdst = -1;
          mktime(&tStack_54);
          uVar12 = json_object_new_int();
          json_object_object_add(uVar9,"timestamp",uVar12);
          sVar8 = strlen(__s);
          uVar12 = json_object_new_string_len(__s,sVar8);
          json_object_object_add(uVar9,"hostname",uVar12);
          pcVar11 = local_a4;
          sVar8 = strlen(local_a4);
          uVar12 = json_object_new_string_len(pcVar11,sVar8);
          json_object_object_add(uVar9,"message",uVar12);
          json_object_array_add(uVar10,uVar9);
        }
        pcVar11 = strsep(&local_a8,"\n");
      } while (pcVar11 != (char *)0x0);
    }
    free(pcVar6);
  }
  qcgires_setcontenttype(iVar2,"application/json");
  uVar9 = json_object_to_json_string(uVar10);
  FCGI_printf("%s",uVar9);
  IPMI_lo_Logout(local_b4);
  iVar13 = json_object_array_length(uVar10);
  iVar5 = 0;
  if (0 < iVar13) {
    do {
      json_object_array_get_idx(uVar10,iVar5);
      iVar5 = iVar5 + 1;
      json_object_put();
    } while (iVar13 != iVar5);
  }
  json_object_put(uVar10);
  if (__ptr != (void *)0x0) {
    free(__ptr);
  }
  if (pcVar3 != (char *)0x0) {
    strcasecmp(pcVar3,"GET");
LAB_000f85f4:
    if (local_bc != 0) {
      json_object_put(local_bc);
    }
  }
LAB_000f8234:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000f8254:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

