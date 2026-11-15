
void login_handler_func(void)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  void *__ptr;
  int iVar4;
  char *__s1;
  char *__s1_00;
  int iVar5;
  char *pcVar6;
  char *__s1_01;
  char *pcVar7;
  undefined4 uVar8;
  uint uVar9;
  char *pcVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  size_t sVar14;
  int iVar15;
  uint uVar16;
  size_t sVar17;
  void *pvVar18;
  char *__s;
  char *local_1fc;
  char *local_1f4;
  uint local_1e4;
  uint local_1e0;
  byte local_1d6;
  undefined1 local_1d5;
  undefined4 local_1d4;
  undefined4 local_1d0;
  int local_1cc;
  void *local_1c8;
  int local_1c4;
  undefined1 auStack_1c0 [8];
  uint local_1b8;
  undefined4 local_1b4;
  undefined2 local_1b0;
  int local_1a4;
  int local_1a0;
  int local_19c;
  undefined4 uStack_198;
  int local_194;
  int local_190;
  int local_18c;
  int local_184;
  int local_180;
  int local_17c;
  undefined4 local_178;
  undefined1 auStack_174 [44];
  undefined1 auStack_148 [44];
  char acStack_11c [48];
  char acStack_ec [48];
  undefined1 auStack_bc [43];
  byte local_91;
  undefined4 local_90;
  stat sStack_80;
  
  iVar2 = qcgireq_parse(0);
  pre_call_hook();
  iVar3 = json_object_new_object();
  __ptr = (void *)qcgireq_getquery(2);
  iVar4 = json_object_new_object();
  __s1 = getenv(DAT_000316c4);
  __s1_00 = getenv(DAT_000316c8);
  if ((__s1 != (char *)0x0) &&
     (iVar5 = strcasecmp(__s1,DAT_000316cc),
     iVar5 != 0 && (__s1_00 != (char *)0x0 && __ptr != (void *)0x0))) {
    json_object_put(iVar4);
    iVar4 = json_tokener_parse(__ptr);
  }
  local_1d4 = 0;
  local_1d0 = 0;
  memset(acStack_11c,0,0x2e);
  memset(acStack_ec,0,0x2e);
  local_1d5 = 1;
  local_1d6 = 0;
  local_1cc = 0;
  local_1c4 = 0;
  pcVar6 = calloc(8,1);
  if (pcVar6 == (char *)0x0) {
    IPMI_lo_Logout(auStack_174);
    if (iVar3 != 0) {
      json_object_put(iVar3);
    }
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (__s1 == (char *)0x0) {
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_00031758,0x1a);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_0003175c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
    }
    else {
      strcasecmp(__s1,DAT_000316cc);
      pcVar6 = __s1_00;
      if (__s1_00 != (char *)0x0) {
        pcVar6 = (char *)0x1;
      }
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_00031758,0x1a);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_0003175c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
        pcVar6 = (char *)0x1;
      }
      iVar3 = strcasecmp(__s1,DAT_000316cc);
      if (iVar3 == 0) {
        pcVar6 = (char *)0x0;
      }
      if (pcVar6 == (char *)0x0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        iVar3 = strcasecmp(__s1,DAT_000317bc);
        if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
    }
    goto LAB_000308b8;
  }
  __s1_01 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_000316d0,0);
  pcVar7 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_000316d4,0);
  iVar5 = isValidFieldname(__s1_01);
  if (iVar5 != 0) {
    if (iVar3 != 0) {
      json_object_put(iVar3);
    }
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (__s1 == (char *)0x0) {
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000316d8,0xc);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(0x20c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000316dc);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
    }
    else {
      strcasecmp(__s1,DAT_000316cc);
      pcVar6 = __s1_00;
      if (__s1_00 != (char *)0x0) {
        pcVar6 = (char *)0x1;
      }
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000316d8,0xc);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(0x20c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000316dc);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
        pcVar6 = (char *)0x1;
      }
      iVar3 = strcasecmp(__s1,DAT_000316cc);
      if (iVar3 == 0) {
        pcVar6 = (char *)0x0;
      }
      if (pcVar6 == (char *)0x0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        iVar3 = strcasecmp(__s1,DAT_000317bc);
        if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
    }
    goto LAB_000308b8;
  }
  iVar5 = isValidFieldname(pcVar7);
  if (iVar5 != 0) {
    if (iVar3 != 0) {
      json_object_put(iVar3);
    }
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (__s1 == (char *)0x0) {
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000316d8,0xc);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(0x20c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000316dc);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
    }
    else {
      strcasecmp(__s1,DAT_000316cc);
      pcVar6 = __s1_00;
      if (__s1_00 != (char *)0x0) {
        pcVar6 = (char *)0x1;
      }
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000316d8,0xc);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(0x20c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000316dc);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
        pcVar6 = (char *)0x1;
      }
      iVar3 = strcasecmp(__s1,DAT_000316cc);
      if (iVar3 == 0) {
        pcVar6 = (char *)0x0;
      }
      if (pcVar6 == (char *)0x0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        iVar3 = strcasecmp(__s1,DAT_000317bc);
        if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
    }
    goto LAB_000308b8;
  }
  if ((*__s1_01 == '\0') || (*pcVar7 == '\0')) {
    free(pcVar6);
    IPMI_lo_Logout(auStack_174);
    if (iVar3 != 0) {
      json_object_put(iVar3);
    }
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (__s1 == (char *)0x0) {
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_000317b4);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
    }
    else {
      strcasecmp(__s1,DAT_000316cc);
      pcVar6 = __s1_00;
      if (__s1_00 != (char *)0x0) {
        pcVar6 = (char *)0x1;
      }
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_000317b4);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
        pcVar6 = (char *)0x1;
      }
      iVar3 = strcasecmp(__s1,DAT_000316cc);
      if (iVar3 == 0) {
        pcVar6 = (char *)0x0;
      }
      if (pcVar6 == (char *)0x0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        iVar3 = strcasecmp(__s1,DAT_000317bc);
        if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
    }
    goto LAB_000308b8;
  }
  uVar9 = getHTTPSEnable();
  pcVar10 = (char *)get_user_agent();
  if (pcVar10 == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00031768,DAT_00031790,DAT_00031764);
  }
  else {
    iVar5 = strncasecmp(pcVar10,DAT_000316e0,7);
    if (iVar5 == 0) {
      local_1b4 = DAT_00031760;
    }
    else {
      iVar5 = strncasecmp(pcVar10,DAT_000316e4,5);
      if (iVar5 == 0) {
        local_1b4 = *(undefined4 *)DAT_000316e4;
        local_1b0 = (undefined2)*(undefined4 *)(DAT_000316e4 + 4);
      }
      else if (uVar9 == 1) {
        local_1b4 = *DAT_000316e8;
        local_1b0 = (undefined2)DAT_000316e8[1];
      }
      else {
        local_1b4 = *DAT_000316ec;
        local_1b0 = CONCAT11(local_1b0._1_1_,(char)DAT_000316ec[1]);
      }
    }
  }
  local_1fc = getenv(DAT_000316f0);
  if (((local_1fc == (char *)0x0) || (pcVar10 = getenv(DAT_000316f4), pcVar10 == (char *)0x0)) ||
     (local_1f4 = getenv(DAT_000316f8), local_1f4 == (char *)0x0)) {
    free(pcVar6);
    IPMI_lo_Logout(auStack_174);
    if (iVar3 != 0) {
      json_object_put(iVar3);
    }
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (__s1 == (char *)0x0) {
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_0003176c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
    }
    else {
      strcasecmp(__s1,DAT_000316cc);
      pcVar6 = __s1_00;
      if (__s1_00 != (char *)0x0) {
        pcVar6 = (char *)0x1;
      }
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_0003176c);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
        pcVar6 = (char *)0x1;
      }
      iVar3 = strcasecmp(__s1,DAT_000316cc);
      if (iVar3 == 0) {
        pcVar6 = (char *)0x0;
      }
      if (pcVar6 == (char *)0x0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        iVar3 = strcasecmp(__s1,DAT_000317bc);
        if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
    }
    goto LAB_000308b8;
  }
  snprintf(acStack_11c,0x2e,DAT_000317e0,local_1fc);
  snprintf(acStack_ec,0x2e,DAT_000317e0,local_1f4);
  local_184 = 0;
  local_180 = 0;
  local_17c = 0;
  local_178 = 0;
  iVar5 = inet_pton(10,acStack_11c,&local_194);
  if (((iVar5 != 0) && (local_194 == 0 && local_190 == 0)) && (local_18c == -0x10000)) {
    local_1fc = local_1fc + 7;
  }
  iVar5 = inet_pton(10,acStack_ec,&local_1a4);
  if (iVar5 != 0) {
    if ((local_1a4 == 0 && local_1a0 == 0) && (local_19c == -0x10000)) {
      local_1f4 = local_1f4 + 7;
      inet_pton(2,local_1f4,&local_184);
    }
    else {
      local_184 = local_1a4;
      local_180 = local_1a0;
      local_17c = local_19c;
      local_178 = uStack_198;
    }
  }
  (**(code **)(iVar2 + 0x18))(iVar2,DAT_000316fc,1);
  iVar5 = is_session_exist();
  if (iVar5 == 1) {
    FCGI_printf(DAT_00031770);
    if (iVar3 != 0) {
      json_object_put(iVar3);
    }
    if (__ptr != (void *)0x0) {
      free(__ptr);
    }
    if (__s1 == (char *)0x0) {
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_000317b4);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
    }
    else {
      strcasecmp(__s1,DAT_000317c0);
      pcVar6 = __s1_00;
      if (__s1_00 != (char *)0x0) {
        pcVar6 = (char *)0x1;
      }
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
      iVar3 = json_object_new_object();
      uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
      json_object_object_add(iVar3,DAT_000317c8,uVar8);
      uVar8 = json_object_new_int(DAT_000317b4);
      json_object_object_add(iVar3,DAT_000317d0,uVar8);
      FCGI_printf(DAT_000317d8,DAT_000317d4);
      qcgires_setcontenttype(iVar2,DAT_000317dc);
      uVar8 = json_object_to_json_string(iVar3);
      FCGI_printf(DAT_000317e0,uVar8);
      if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
        pcVar6 = (char *)0x1;
      }
      iVar3 = strcasecmp(__s1,DAT_000317c0);
      if (iVar3 == 0) {
        pcVar6 = (char *)0x0;
      }
      if (pcVar6 == (char *)0x0) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else {
        iVar3 = strcasecmp(__s1,DAT_000317bc);
        if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
    }
    goto LAB_000308b8;
  }
  uVar11 = DoPAMAuthentication(&local_1d4,__s1_01,pcVar7,auStack_1c0,&local_1b4,local_1fc,local_1f4)
  ;
  if ((uVar11 & 0xffffffef) != 0) {
    free(pcVar6);
    iVar5 = IsCardInFlashMode();
    if (iVar5 == 0) {
      IPMI_lo_Logout(auStack_174);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (__s1 == (char *)0x0) {
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
        json_object_object_add(iVar3,DAT_000317c8,uVar8);
        uVar8 = json_object_new_int(DAT_000317b4);
        json_object_object_add(iVar3,DAT_000317d0,uVar8);
        FCGI_printf(DAT_000317d8,DAT_000317d4);
        qcgires_setcontenttype(iVar2,DAT_000317dc);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000317e0,uVar8);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
      }
      else {
        strcasecmp(__s1,DAT_000317c0);
        pcVar6 = __s1_00;
        if (__s1_00 != (char *)0x0) {
          pcVar6 = (char *)0x1;
        }
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
        json_object_object_add(iVar3,DAT_000317c8,uVar8);
        uVar8 = json_object_new_int(DAT_000317b4);
        json_object_object_add(iVar3,DAT_000317d0,uVar8);
        FCGI_printf(DAT_000317d8,DAT_000317d4);
        qcgires_setcontenttype(iVar2,DAT_000317dc);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000317e0,uVar8);
        if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
          pcVar6 = (char *)0x1;
        }
        iVar3 = strcasecmp(__s1,DAT_000317c0);
        if (iVar3 == 0) {
          pcVar6 = (char *)0x0;
        }
        if (pcVar6 == (char *)0x0) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else {
          iVar3 = strcasecmp(__s1,DAT_000317bc);
          if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
      }
    }
    else {
      IPMI_lo_Logout(auStack_174);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (__s1 == (char *)0x0) {
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
        json_object_object_add(iVar3,DAT_000317c8,uVar8);
        uVar8 = json_object_new_int(DAT_000317b0);
        json_object_object_add(iVar3,DAT_000317d0,uVar8);
        FCGI_printf(DAT_000317d8,DAT_000317d4);
        qcgires_setcontenttype(iVar2,DAT_000317dc);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000317e0,uVar8);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
      }
      else {
        strcasecmp(__s1,DAT_000317c0);
        pcVar6 = __s1_00;
        if (__s1_00 != (char *)0x0) {
          pcVar6 = (char *)0x1;
        }
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
        json_object_object_add(iVar3,DAT_000317c8,uVar8);
        uVar8 = json_object_new_int(DAT_000317b0);
        json_object_object_add(iVar3,DAT_000317d0,uVar8);
        FCGI_printf(DAT_000317d8,DAT_000317d4);
        qcgires_setcontenttype(iVar2,DAT_000317dc);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000317e0,uVar8);
        if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
          pcVar6 = (char *)0x1;
        }
        iVar3 = strcasecmp(__s1,DAT_000317c0);
        if (iVar3 == 0) {
          pcVar6 = (char *)0x0;
        }
        if (pcVar6 == (char *)0x0) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else {
          iVar3 = strcasecmp(__s1,DAT_000317bc);
          if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
      }
    }
    goto LAB_000308b8;
  }
  iVar5 = qcgisess_init(iVar2);
  if (iVar5 != 0) {
    (**(code **)(iVar2 + 0xc))(iVar5,DAT_00031700,1);
    gen_random(pcVar6,8);
    uVar12 = GetUsrLANChPriv(auStack_1c0,&local_184);
    if (3 < uVar12 - 2) {
      free(pcVar6);
      IPMI_lo_Logout(auStack_174);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (__s1 == (char *)0x0) {
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
        json_object_object_add(iVar3,DAT_000331b4,uVar8);
        uVar8 = json_object_new_int(DAT_000331b8);
        json_object_object_add(iVar3,DAT_000331bc,uVar8);
        FCGI_printf(DAT_000331c4,DAT_000331c0);
        qcgires_setcontenttype(iVar2,DAT_000331c8);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000331cc,uVar8);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
      }
      else {
        strcasecmp(__s1,DAT_000317c0);
        pcVar6 = __s1_00;
        if (__s1_00 != (char *)0x0) {
          pcVar6 = (char *)0x1;
        }
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
        json_object_object_add(iVar3,DAT_000317c8,uVar8);
        uVar8 = json_object_new_int(DAT_00031788);
        json_object_object_add(iVar3,DAT_000317d0,uVar8);
        FCGI_printf(DAT_000317d8,DAT_000317d4);
        qcgires_setcontenttype(iVar2,DAT_000317dc);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000317e0,uVar8);
        if ((iVar3 != 0) && (json_object_put(iVar3), pcVar6 = __s1_00, __s1_00 != (char *)0x0)) {
          pcVar6 = (char *)0x1;
        }
        iVar3 = strcasecmp(__s1,DAT_000317c0);
        if (iVar3 == 0) {
          pcVar6 = (char *)0x0;
        }
        if (pcVar6 == (char *)0x0) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else {
          iVar3 = strcasecmp(__s1,DAT_000331d0);
          if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
      }
      goto LAB_000308b8;
    }
    uVar16 = DAT_00031708;
    if (*(int *)(DAT_00031704 + 0x54) == 1) {
      iVar13 = get_service_configurations(DAT_00031774,auStack_bc);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0003177c,DAT_00031790,DAT_00031778,iVar13);
      if (iVar13 == -1) {
        free(pcVar6);
        IPMI_lo_Logout(auStack_174);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (__s1 == (char *)0x0) {
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
          json_object_object_add(iVar3,DAT_000331b4,uVar8);
          uVar8 = json_object_new_int(DAT_000331dc);
          json_object_object_add(iVar3,DAT_000331bc,uVar8);
          FCGI_printf(DAT_000331c4,DAT_000331c0);
          qcgires_setcontenttype(iVar2,DAT_000331c8);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000331cc,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
        }
        else {
          strcasecmp(__s1,DAT_000331ac);
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
          json_object_object_add(iVar3,DAT_000331b4,uVar8);
          uVar8 = json_object_new_int(DAT_000331dc);
          json_object_object_add(iVar3,DAT_000331bc,uVar8);
          FCGI_printf(DAT_000331c4,DAT_000331c0);
          qcgires_setcontenttype(iVar2,DAT_000331c8);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000331cc,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          iVar3 = strcasecmp(__s1,DAT_000331ac);
          if (__s1_00 == (char *)0x0 || iVar3 == 0) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else {
            iVar3 = strcasecmp(__s1,DAT_000331d0);
            if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
        }
        goto LAB_000308b8;
      }
      uVar16 = (uint)local_91 | local_90 << 8;
    }
    qcgisess_settimeout(iVar5,uVar16);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_0003170c,uVar12,1);
    if (*(int *)(DAT_00031704 + 0x138) == 1) {
      local_1e0 = local_1b8;
      if (uVar12 != 2) goto LAB_00031b3c;
    }
    else {
      if ((int)uVar12 < 4) {
        local_1e0 = 0;
        if (uVar12 == 2) {
          local_1e0 = 0;
          goto LAB_00030c80;
        }
      }
      else {
        local_1e0 = 3;
      }
LAB_00031b3c:
      local_1e0 = local_1e0 | 0x100;
    }
LAB_00030c80:
    iVar13 = LIBIPMI_HL_AMIGetUDSInfo(&local_184,0,&local_1d5,0,10);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00031714,DAT_00031790,DAT_00031710,iVar13);
    if (iVar13 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00031794,DAT_00031790,DAT_0003178c,iVar13);
      IPMI_lo_Logout(auStack_174);
      if (iVar3 != 0) {
        json_object_put(iVar3);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (__s1 == (char *)0x0) {
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
        json_object_object_add(iVar3,DAT_000331b4,uVar8);
        uVar8 = json_object_new_int(DAT_000331d4);
        json_object_object_add(iVar3,DAT_000331bc,uVar8);
        FCGI_printf(DAT_000331c4,DAT_000331c0);
        qcgires_setcontenttype(iVar2,DAT_000331c8);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000331cc,uVar8);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
      }
      else {
        strcasecmp(__s1,DAT_000317c0);
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
        iVar3 = json_object_new_object();
        uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
        json_object_object_add(iVar3,DAT_000317c8,uVar8);
        uVar8 = json_object_new_int(DAT_00031798);
        json_object_object_add(iVar3,DAT_000317d0,uVar8);
        FCGI_printf(DAT_000317d8,DAT_000317d4);
        qcgires_setcontenttype(iVar2,DAT_000317dc);
        uVar8 = json_object_to_json_string(iVar3);
        FCGI_printf(DAT_000317e0,uVar8);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
        iVar3 = strcasecmp(__s1,DAT_000317c0);
        if (iVar3 == 0 || __s1_00 == (char *)0x0) {
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
        else {
          iVar3 = strcasecmp(__s1,DAT_000331d0);
          if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else if (iVar4 != 0) {
            json_object_put(iVar4);
          }
        }
      }
      goto LAB_000308b8;
    }
    if (*(int *)(DAT_00031704 + 0x1e0) == 1) {
      iVar13 = racsessinfo_getallrecords(&local_1c8,auStack_148,&local_1c4);
      if (iVar13 != 0) {
        if (local_1c8 != (void *)0x0) {
          free(local_1c8);
        }
        free(pcVar6);
        IPMI_lo_Logout(auStack_174);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (__s1 == (char *)0x0) {
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
          json_object_object_add(iVar3,DAT_000331b4,uVar8);
          uVar8 = json_object_new_int(DAT_000331e8);
          json_object_object_add(iVar3,DAT_000331bc,uVar8);
          FCGI_printf(DAT_000331c4,DAT_000331c0);
          qcgires_setcontenttype(iVar2,DAT_000331c8);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000331cc,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
        }
        else {
          strcasecmp(__s1,DAT_000317c0);
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
          json_object_object_add(iVar3,DAT_000317c8,uVar8);
          uVar8 = json_object_new_int(DAT_000317b8);
          json_object_object_add(iVar3,DAT_000317d0,uVar8);
          FCGI_printf(DAT_000317d8,DAT_000317d4);
          qcgires_setcontenttype(iVar2,DAT_000317dc);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000317e0,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          iVar3 = strcasecmp(__s1,DAT_000317c0);
          if (iVar3 == 0 || __s1_00 == (char *)0x0) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else {
            iVar3 = strcasecmp(__s1,DAT_000331d0);
            if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
        }
        goto LAB_000308b8;
      }
      if (local_1c4 != 0) {
        pvVar18 = (void *)(local_1c4 * 0x73 + (int)local_1c8);
        iVar13 = 0;
        do {
          pbVar1 = (byte *)((int)local_1c8 + 8);
          local_1c8 = (void *)((int)local_1c8 + 0x73);
          if (*pbVar1 < 2) {
            iVar13 = iVar13 + 1;
          }
        } while (pvVar18 != local_1c8);
        if (0x13 < iVar13) {
          free(pcVar6);
          IPMI_lo_Logout(auStack_174);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (__s1 == (char *)0x0) {
            iVar3 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
            json_object_object_add(iVar3,DAT_000331b4,uVar8);
            uVar8 = json_object_new_int(DAT_000331d8);
            json_object_object_add(iVar3,DAT_000331bc,uVar8);
            FCGI_printf(DAT_000331c4,DAT_000331c0);
            qcgires_setcontenttype(iVar2,DAT_000331c8);
            uVar8 = json_object_to_json_string(iVar3);
            FCGI_printf(DAT_000331cc,uVar8);
            if (iVar3 != 0) {
              json_object_put(iVar3);
            }
          }
          else {
            strcasecmp(__s1,DAT_000331ac);
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
            iVar3 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
            json_object_object_add(iVar3,DAT_000331b4,uVar8);
            uVar8 = json_object_new_int(DAT_000331d8);
            json_object_object_add(iVar3,DAT_000331bc,uVar8);
            FCGI_printf(DAT_000331c4,DAT_000331c0);
            qcgires_setcontenttype(iVar2,DAT_000331c8);
            uVar8 = json_object_to_json_string(iVar3);
            FCGI_printf(DAT_000331cc,uVar8);
            if (iVar3 != 0) {
              json_object_put(iVar3);
            }
            iVar3 = strcasecmp(__s1,DAT_000331ac);
            if (iVar3 == 0 || __s1_00 == (char *)0x0) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else {
              iVar3 = strcasecmp(__s1,DAT_000331d0);
              if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
                if (iVar4 != 0) {
                  json_object_put(iVar4);
                }
              }
              else if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
          }
          goto LAB_000308b8;
        }
      }
      iVar13 = 0;
      pcVar7 = DAT_000317a4;
      do {
        iVar15 = strcmp(__s1_01,pcVar7);
        if (iVar15 == 0) {
          iVar15 = __xstat(3,DAT_000317a0,&sStack_80);
          if ((iVar15 != 0) ||
             (sStack_80.st_mtim.tv_sec <= *(int *)(DAT_000317a4 + iVar13 * 0x18 + 0x14))) {
            local_1e4 = (uint)(byte)DAT_000317a4[iVar13 * 0x18 + 0x11];
            goto LAB_000322c0;
          }
          break;
        }
        iVar13 = iVar13 + 1;
        pcVar7 = pcVar7 + 0x18;
      } while (iVar13 != 0x10);
      local_1e4 = MapUid_to_SELUid(__s1_01,0);
      pcVar7 = DAT_000317e0;
      if (local_1e4 < 0x10) {
        __s = DAT_000317a4 + local_1e4 * 0x18;
        __s[0x11] = (char)local_1e4;
        uVar16 = snprintf(__s,0x11,pcVar7,__s1_01);
        if (0x10 < uVar16) {
          free(pcVar6);
          IPMI_lo_Logout(auStack_174);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (__s1 == (char *)0x0) {
            iVar3 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_000331f0,0xf);
            json_object_object_add(iVar3,DAT_000331b4,uVar8);
            uVar8 = json_object_new_int(DAT_000331f4);
            json_object_object_add(iVar3,DAT_000331bc,uVar8);
            FCGI_printf(DAT_000331c4,DAT_000331c0);
            qcgires_setcontenttype(iVar2,DAT_000331c8);
            uVar8 = json_object_to_json_string(iVar3);
            FCGI_printf(DAT_000331cc,uVar8);
            if (iVar3 != 0) {
              json_object_put(iVar3);
            }
          }
          else {
            strcasecmp(__s1,DAT_000317c0);
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
            iVar3 = json_object_new_object();
            uVar8 = json_object_new_string_len(DAT_00031780,0xf);
            json_object_object_add(iVar3,DAT_000317c8,uVar8);
            uVar8 = json_object_new_int(DAT_00031784);
            json_object_object_add(iVar3,DAT_000317d0,uVar8);
            FCGI_printf(DAT_000317d8,DAT_000317d4);
            qcgires_setcontenttype(iVar2,DAT_000317dc);
            uVar8 = json_object_to_json_string(iVar3);
            FCGI_printf(DAT_000317e0,uVar8);
            if (iVar3 != 0) {
              json_object_put(iVar3);
            }
            iVar3 = strcasecmp(__s1,DAT_000317c0);
            if (iVar3 == 0 || __s1_00 == (char *)0x0) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else {
              iVar3 = strcasecmp(__s1,DAT_000331d0);
              if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
                if (iVar4 != 0) {
                  json_object_put(iVar4);
                }
              }
              else if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
          }
          goto LAB_000308b8;
        }
        time((time_t *)(DAT_000331ec + local_1e4 * 0x18 + 0x14));
      }
LAB_000322c0:
      sVar14 = strlen(local_1fc);
      sVar17 = strlen(__s1_01);
      racsessinfo_register_session
                (uVar9 & 0xff,local_1fc,sVar14 & 0xff,4,__s1_01,sVar17 & 0xff,uVar12 & 0xff,
                 local_1e4,&local_1d0);
      (**(code **)(iVar5 + 0xc))(iVar5,DAT_000317a8,local_1d0,1);
    }
    else {
      iVar13 = isNotEditable((int)&local_90 + 3,1);
      if (iVar13 != 0) {
        getNotEditableData((int)&local_90 + 3,1,&local_1cc);
      }
      iVar13 = get_active_session(0,&local_1d6);
      if (iVar13 != 0) {
        free(pcVar6);
        IPMI_lo_Logout(auStack_174);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (__s1 == (char *)0x0) {
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
          json_object_object_add(iVar3,DAT_000331b4,uVar8);
          uVar8 = json_object_new_int(DAT_000331e0);
          json_object_object_add(iVar3,DAT_000331bc,uVar8);
          FCGI_printf(DAT_000331c4,DAT_000331c0);
          qcgires_setcontenttype(iVar2,DAT_000331c8);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000331cc,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
        }
        else {
          strcasecmp(__s1,DAT_000317c0);
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
          json_object_object_add(iVar3,DAT_000317c8,uVar8);
          uVar8 = json_object_new_int(DAT_000317ac);
          json_object_object_add(iVar3,DAT_000317d0,uVar8);
          FCGI_printf(DAT_000317d8,DAT_000317d4);
          qcgires_setcontenttype(iVar2,DAT_000317dc);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000317e0,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          iVar3 = strcasecmp(__s1,DAT_000317c0);
          if (__s1_00 == (char *)0x0 || iVar3 == 0) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else {
            iVar3 = strcasecmp(__s1,DAT_000331d0);
            if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
        }
        goto LAB_000308b8;
      }
      local_1d6 = local_1d6 + 1;
      if (local_1cc < (int)(uint)local_1d6) {
        free(pcVar6);
        IPMI_lo_Logout(auStack_174);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (__s1 == (char *)0x0) {
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
          json_object_object_add(iVar3,DAT_000331b4,uVar8);
          uVar8 = json_object_new_int(DAT_000331d8);
          json_object_object_add(iVar3,DAT_000331bc,uVar8);
          FCGI_printf(DAT_000331c4,DAT_000331c0);
          qcgires_setcontenttype(iVar2,DAT_000331c8);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000331cc,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
        }
        else {
          strcasecmp(__s1,DAT_000317c0);
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
          json_object_object_add(iVar3,DAT_000317c8,uVar8);
          uVar8 = json_object_new_int(DAT_0003179c);
          json_object_object_add(iVar3,DAT_000317d0,uVar8);
          FCGI_printf(DAT_000317d8,DAT_000317d4);
          qcgires_setcontenttype(iVar2,DAT_000317dc);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000317e0,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          iVar3 = strcasecmp(__s1,DAT_000317c0);
          if (__s1_00 == (char *)0x0 || iVar3 == 0) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else {
            iVar3 = strcasecmp(__s1,DAT_000331d0);
            if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
        }
        goto LAB_000308b8;
      }
      iVar13 = set_active_session();
      if (iVar13 != 0) {
        free(pcVar6);
        IPMI_lo_Logout(auStack_174);
        if (iVar3 != 0) {
          json_object_put(iVar3);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (__s1 == (char *)0x0) {
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000331b0,0xf);
          json_object_object_add(iVar3,DAT_000331b4,uVar8);
          uVar8 = json_object_new_int(DAT_000331e4);
          json_object_object_add(iVar3,DAT_000331bc,uVar8);
          FCGI_printf(DAT_000331c4,DAT_000331c0);
          qcgires_setcontenttype(iVar2,DAT_000331c8);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000331cc,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
        }
        else {
          strcasecmp(__s1,DAT_000317c0);
          if (iVar4 != 0) {
            json_object_put(iVar4);
          }
          iVar3 = json_object_new_object();
          uVar8 = json_object_new_string_len(DAT_000317c4,0xf);
          json_object_object_add(iVar3,DAT_000317c8,uVar8);
          uVar8 = json_object_new_int(DAT_000317cc);
          json_object_object_add(iVar3,DAT_000317d0,uVar8);
          FCGI_printf(DAT_000317d8,DAT_000317d4);
          qcgires_setcontenttype(iVar2,DAT_000317dc);
          uVar8 = json_object_to_json_string(iVar3);
          FCGI_printf(DAT_000317e0,uVar8);
          if (iVar3 != 0) {
            json_object_put(iVar3);
          }
          iVar3 = strcasecmp(__s1,DAT_000331ac);
          if (__s1_00 == (char *)0x0 || iVar3 == 0) {
            if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
          else {
            iVar3 = strcasecmp(__s1,DAT_000331d0);
            if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000331c8,0x10), iVar3 == 0)) {
              if (iVar4 != 0) {
                json_object_put(iVar4);
              }
            }
            else if (iVar4 != 0) {
              json_object_put(iVar4);
            }
          }
        }
        goto LAB_000308b8;
      }
      local_1e4 = 0xffffffff;
    }
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_00031718,local_1b8,1);
    (**(code **)(iVar5 + 4))(iVar5,DAT_000316d0,__s1_01,1);
    (**(code **)(iVar5 + 4))(iVar5,DAT_0003171c,pcVar6,1);
    (**(code **)(iVar5 + 4))(iVar5,DAT_00031720,local_1fc,1);
    (**(code **)(iVar5 + 4))(iVar5,DAT_00031724,pcVar10,1);
    (**(code **)(iVar5 + 4))(iVar5,DAT_00031728,local_1f4,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_0003172c,uVar9,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_00031730,local_1d4,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_00031734,0xffffffff,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_00031738,uVar11 == 0x10,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_0003173c,local_1e4,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_00031740,local_1d5,1);
    (**(code **)(iVar5 + 0xc))(iVar5,DAT_00031744,local_1e0,1);
    qcgisess_save(iVar5);
    (**(code **)(iVar5 + 0x58))(iVar5);
    if (uVar11 == 0x10) {
      uVar8 = 0x10;
    }
    else {
      uVar8 = 0;
    }
    uVar8 = json_object_new_int(uVar8);
    json_object_object_add(iVar3,DAT_00031748,uVar8);
    uVar8 = json_object_new_int(uVar12);
    json_object_object_add(iVar3,DAT_0003174c,uVar8);
    uVar8 = json_object_new_int(local_1e4);
    json_object_object_add(iVar3,DAT_0003173c,uVar8);
    uVar8 = json_object_new_int(local_1e0);
    json_object_object_add(iVar3,DAT_00031718,uVar8);
    uVar8 = json_object_new_int(local_1d0);
    json_object_object_add(iVar3,DAT_000317a8,uVar8);
    sVar14 = strlen(local_1fc);
    uVar8 = json_object_new_string_len(local_1fc,sVar14);
    json_object_object_add(iVar3,DAT_00031720,uVar8);
    sVar14 = strlen(pcVar10);
    uVar8 = json_object_new_string_len(pcVar10,sVar14);
    json_object_object_add(iVar3,DAT_00031724,uVar8);
    sVar14 = strlen(local_1f4);
    uVar8 = json_object_new_string_len(local_1f4,sVar14);
    json_object_object_add(iVar3,DAT_00031728,uVar8);
    uVar8 = json_object_new_int(uVar9);
    json_object_object_add(iVar3,DAT_0003172c,uVar8);
    sVar14 = strlen(pcVar6);
    uVar8 = json_object_new_string_len(pcVar6,sVar14);
    json_object_object_add(iVar3,DAT_00031750,uVar8);
    uVar8 = json_object_new_int(local_1d5);
    json_object_object_add(iVar3,DAT_00031754,uVar8);
    uVar8 = json_object_new_int(uVar11 == 0x10);
    json_object_object_add(iVar3,DAT_00031738,uVar8);
  }
  IPMI_lo_Logout(auStack_174);
  free(pcVar6);
  qcgires_setcontenttype(iVar2,DAT_000317dc);
  uVar8 = json_object_to_json_string(iVar3);
  FCGI_printf(DAT_000317e0,uVar8);
  if (iVar3 != 0) {
    json_object_put(iVar3);
  }
  if (__ptr != (void *)0x0) {
    free(__ptr);
  }
  if (__s1 != (char *)0x0) {
    iVar3 = strcasecmp(__s1,DAT_000316cc);
    if (iVar3 == 0 || __s1_00 == (char *)0x0) {
      if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
    else {
      iVar3 = strcasecmp(__s1,DAT_000317bc);
      if ((iVar3 == 0) && (iVar3 = strncasecmp(__s1_00,DAT_000317dc,0x10), iVar3 == 0)) {
        if (iVar4 != 0) {
          json_object_put(iVar4);
        }
      }
      else if (iVar4 != 0) {
        json_object_put(iVar4);
      }
    }
  }
LAB_000308b8:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

