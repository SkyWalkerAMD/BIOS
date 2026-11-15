
void getAuditLog_func(void)

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
  int iVar11;
  char *pcVar12;
  char *__s;
  int iVar13;
  undefined4 uVar14;
  int local_fc;
  undefined1 *local_f4;
  char *local_e0;
  char *local_dc;
  undefined1 auStack_d8 [44];
  tm tStack_ac;
  stat sStack_80;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0010d058);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0010d068);
    FCGI_printf(DAT_0010d06c);
    qcgires_setcontenttype(iVar2,DAT_0010d070);
    uVar10 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_0010d074,uVar9);
    uVar9 = json_object_new_string(DAT_0010d078);
    json_object_object_add(uVar10,DAT_0010d07c,uVar9);
    uVar9 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_0010d080,uVar9);
    json_object_put(uVar10);
    goto LAB_0010c54c;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0010d05c);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0010d060,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0010d060,0);
    sVar8 = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,sVar8);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0010d064), iVar5 != 0))
    goto LAB_0010c49c;
    pre_authorized_call_hook(iVar2,iVar4);
    uVar10 = json_object_new_array();
    __ptr = (void *)qcgireq_getquery(4);
    local_fc = json_object_new_object();
    pcVar3 = getenv(DAT_0010d088);
    pcVar6 = getenv(DAT_0010d08c);
    if ((pcVar3 != (char *)0x0) &&
       (iVar5 = strcasecmp(pcVar3,DAT_0010d090),
       iVar5 != 0 && (__ptr != (void *)0x0 && pcVar6 != (char *)0x0))) {
      json_object_put(local_fc);
      local_fc = json_tokener_parse(__ptr);
    }
    if (*DAT_0010d094 == 0) {
LAB_0010c65c:
      local_f4 = auStack_d8;
      local_e0 = (char *)0x0;
      local_dc = (char *)0x0;
      iVar5 = (**(code **)(iVar2 + 0x24))(iVar2,DAT_0010d0a0);
      memset(&tStack_ac,0,0x2c);
      iVar11 = __xstat(3,DAT_0010d0a4,&sStack_80);
      if (iVar11 == 0) {
        local_e0 = (char *)fileread(DAT_0010d0a4);
        if (local_e0 == (char *)0x0) {
          IPMI_lo_Logout(local_f4);
          iVar11 = json_object_array_length(uVar10);
          iVar5 = 0;
          if (0 < iVar11) {
            do {
              json_object_array_get_idx(uVar10,iVar5);
              iVar5 = iVar5 + 1;
              json_object_put();
            } while (iVar11 != iVar5);
          }
          json_object_put(uVar10);
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            iVar5 = strcasecmp(pcVar3,DAT_0010d090);
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_0010d0f4), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_0010d070,0x10);
            }
            if (local_fc != 0) {
              json_object_put(local_fc);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_0010d0bc,0x1b);
            json_object_object_add(iVar5,DAT_0010d07c,uVar10);
            uVar10 = DAT_0010d0f0;
LAB_0010c9f4:
            uVar10 = json_object_new_int(uVar10);
            json_object_object_add(iVar5,DAT_0010d0c4,uVar10);
            FCGI_printf(DAT_0010d0cc,DAT_0010d0c8);
            qcgires_setcontenttype(iVar2,DAT_0010d070);
            uVar10 = json_object_to_json_string(iVar5);
            FCGI_printf(DAT_0010d080,uVar10);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            strcasecmp(pcVar3,DAT_0010d090);
            goto LAB_0010cb88;
          }
          local_fc = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_0010d0bc,0x1b);
          json_object_object_add(local_fc,DAT_0010d07c,uVar10);
          uVar10 = DAT_0010d0f0;
          goto LAB_0010ce6c;
        }
LAB_0010c6bc:
        pcVar7 = local_e0;
        pcVar12 = strsep(&local_e0,DAT_0010d0a8);
        pcVar6 = DAT_0010d0ac;
        if (pcVar12 == (char *)0x0) {
          iVar11 = 1;
          uVar9 = 0;
        }
        else {
          iVar11 = 1;
          do {
            uVar9 = json_object_new_object();
            if (iVar5 == 0) {
              uVar14 = json_object_new_int(iVar11);
              json_object_object_add(uVar9,DAT_0010d0b4,uVar14);
            }
            strtok_r(pcVar12,pcVar6,&local_dc);
            pcVar12 = strtok_r((char *)0x0,pcVar6,&local_dc);
            __s = strtok_r((char *)0x0,pcVar6,&local_dc);
            iVar11 = iVar11 + 1;
            if ((pcVar12 == (char *)0x0) ||
               (iVar13 = __isoc99_sscanf(pcVar12,DAT_0010d0b0,&tStack_ac.tm_year,&tStack_ac.tm_mon,
                                         &tStack_ac.tm_mday,&tStack_ac.tm_hour,&tStack_ac.tm_min,
                                         &tStack_ac), iVar13 != 6)) {
LAB_0010c7a4:
              pcVar12 = strsep(&local_e0,DAT_0010d0a8);
            }
            else {
              tStack_ac.tm_year = tStack_ac.tm_year + -0x76c;
              tStack_ac.tm_mon = tStack_ac.tm_mon + -1;
              tStack_ac.tm_isdst = -1;
              mktime(&tStack_ac);
              if (iVar5 != 0) goto LAB_0010c7a4;
              uVar14 = json_object_new_int();
              json_object_object_add(uVar9,DAT_0010d0d8,uVar14);
              sVar8 = strlen(__s);
              uVar14 = json_object_new_string_len(__s,sVar8);
              json_object_object_add(uVar9,DAT_0010d0dc,uVar14);
              pcVar12 = local_dc;
              sVar8 = strlen(local_dc);
              uVar14 = json_object_new_string_len(pcVar12,sVar8);
              json_object_object_add(uVar9,DAT_0010d0e0,uVar14);
              pcVar12 = strsep(&local_e0,DAT_0010d0a8);
              json_object_array_add(uVar10,uVar9);
            }
          } while (pcVar12 != (char *)0x0);
        }
        if (iVar5 == 1) {
          uVar14 = json_object_new_int(iVar11 + -1);
          json_object_object_add(uVar9,DAT_0010d0d4,uVar14);
          json_object_array_add(uVar10,uVar9);
        }
        free(pcVar7);
        qcgires_setcontenttype(iVar2,DAT_0010d070);
        uVar9 = json_object_to_json_string(uVar10);
        FCGI_printf(DAT_0010d080,uVar9);
        IPMI_lo_Logout(local_f4);
        iVar11 = json_object_array_length(uVar10);
        iVar5 = 0;
        if (0 < iVar11) {
          do {
            json_object_array_get_idx(uVar10,iVar5);
            iVar5 = iVar5 + 1;
            json_object_put();
          } while (iVar11 != iVar5);
        }
        json_object_put(uVar10);
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 != (char *)0x0) {
          strcasecmp(pcVar3,DAT_0010d090);
          goto LAB_0010c88c;
        }
      }
      else {
        iVar11 = __xstat(3,DAT_0010d0b8,&sStack_80);
        if (iVar11 == 0) {
          local_e0 = (char *)fileread(DAT_0010d0b8);
          if (local_e0 != (char *)0x0) goto LAB_0010c6bc;
          IPMI_lo_Logout(local_f4);
          iVar11 = json_object_array_length(uVar10);
          iVar5 = 0;
          if (0 < iVar11) {
            do {
              json_object_array_get_idx(uVar10,iVar5);
              iVar5 = iVar5 + 1;
              json_object_put();
            } while (iVar11 != iVar5);
          }
          json_object_put(uVar10);
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            iVar5 = strcasecmp(pcVar3,DAT_0010d090);
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_0010d0f4), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_0010d070,0x10);
            }
            if (local_fc != 0) {
              json_object_put(local_fc);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_0010d0bc,0x1b);
            json_object_object_add(iVar5,DAT_0010d07c,uVar10);
            uVar10 = DAT_0010d0c0;
            goto LAB_0010c9f4;
          }
          local_fc = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_0010d0bc,0x1b);
          json_object_object_add(local_fc,DAT_0010d07c,uVar10);
          uVar10 = DAT_0010d0c0;
        }
        else {
          IPMI_lo_Logout(local_f4);
          iVar11 = json_object_array_length(uVar10);
          iVar5 = 0;
          if (0 < iVar11) {
            do {
              json_object_array_get_idx(uVar10,iVar5);
              iVar5 = iVar5 + 1;
              json_object_put();
            } while (iVar11 != iVar5);
          }
          json_object_put(uVar10);
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            iVar5 = strcasecmp(pcVar3,DAT_0010d090);
            pcVar7 = pcVar6;
            if (pcVar6 != (char *)0x0) {
              pcVar7 = (char *)0x1;
            }
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_0010d0f4), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_0010d070,0x10);
            }
            if (local_fc != 0) {
              json_object_put(local_fc);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_0010d0bc,0x1b);
            json_object_object_add(iVar5,DAT_0010d07c,uVar10);
            uVar10 = json_object_new_int(DAT_0010d0d0);
            json_object_object_add(iVar5,DAT_0010d0c4,uVar10);
            FCGI_printf(DAT_0010d0cc,DAT_0010d0c8);
            qcgires_setcontenttype(iVar2,DAT_0010d070);
            uVar10 = json_object_to_json_string(iVar5);
            FCGI_printf(DAT_0010d080,uVar10);
            if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
              pcVar7 = (char *)0x1;
            }
            iVar5 = strcasecmp(pcVar3,DAT_0010d090);
            if (iVar5 == 0) {
              pcVar7 = (char *)0x0;
            }
            if (pcVar7 == (char *)0x0) goto LAB_0010c88c;
            goto LAB_0010cb88;
          }
          local_fc = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_0010d0bc,0x1b);
          json_object_object_add(local_fc,DAT_0010d07c,uVar10);
          uVar10 = DAT_0010d0d0;
        }
LAB_0010ce6c:
        uVar10 = json_object_new_int(uVar10);
        json_object_object_add(local_fc,DAT_0010d0c4,uVar10);
        uVar10 = DAT_0010d0c8;
LAB_0010ce84:
        FCGI_printf(DAT_0010d0cc,uVar10);
        qcgires_setcontenttype(iVar2,DAT_0010d070);
        uVar10 = json_object_to_json_string(local_fc);
        FCGI_printf(DAT_0010d080,uVar10);
        if (local_fc != 0) goto LAB_0010cb94;
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0010d098);
      iVar5 = IPMI_lo_Login(DAT_0010d09c,DAT_0010d09c,auStack_d8,uVar1,1,0,0,0);
      if (iVar5 == 0) goto LAB_0010c65c;
      IPMI_lo_Logout(auStack_d8);
      iVar11 = json_object_array_length(uVar10);
      iVar5 = 0;
      if (0 < iVar11) {
        do {
          json_object_array_get_idx(uVar10,iVar5);
          iVar5 = iVar5 + 1;
          json_object_put();
        } while (iVar11 != iVar5);
      }
      json_object_put(uVar10);
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        local_fc = json_object_new_object();
        uVar10 = json_object_new_string_len(DAT_0010d0e4,0x20);
        json_object_object_add(local_fc,DAT_0010d07c,uVar10);
        uVar10 = json_object_new_int(DAT_0010d0e8);
        json_object_object_add(local_fc,DAT_0010d0c4,uVar10);
        uVar10 = DAT_0010d0ec;
        goto LAB_0010ce84;
      }
      iVar5 = strcasecmp(pcVar3,DAT_0010d090);
      pcVar7 = pcVar6;
      if (pcVar6 != (char *)0x0) {
        pcVar7 = (char *)0x1;
      }
      if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
         (iVar5 = strcasecmp(pcVar3,DAT_0010d0f4), iVar5 == 0)) {
        strncasecmp(pcVar6,DAT_0010d070,0x10);
      }
      if (local_fc != 0) {
        json_object_put(local_fc);
      }
      iVar5 = json_object_new_object();
      uVar10 = json_object_new_string_len(DAT_0010d0e4,0x20);
      json_object_object_add(iVar5,DAT_0010d07c,uVar10);
      uVar10 = json_object_new_int(DAT_0010d0e8);
      json_object_object_add(iVar5,DAT_0010d0c4,uVar10);
      FCGI_printf(DAT_0010d0cc,DAT_0010d0ec);
      qcgires_setcontenttype(iVar2,DAT_0010d070);
      uVar10 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0010d080,uVar10);
      if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
        pcVar7 = (char *)0x1;
      }
      iVar5 = strcasecmp(pcVar3,DAT_0010d090);
      if (iVar5 == 0) {
        pcVar7 = (char *)0x0;
      }
      if (pcVar7 != (char *)0x0) {
LAB_0010c88c:
        if (local_fc != 0) {
          json_object_put(local_fc);
        }
        goto LAB_0010c52c;
      }
LAB_0010cb88:
      if (local_fc == 0) goto LAB_0010c52c;
LAB_0010cb94:
      json_object_put(local_fc);
    }
  }
  else {
LAB_0010c49c:
    FCGI_printf(DAT_0010d068);
    FCGI_printf(DAT_0010d06c);
    qcgires_setcontenttype(iVar2,DAT_0010d070);
    uVar9 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_0010d074,uVar10);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0010d064);
    uVar10 = DAT_0010d078;
    if (iVar5 == 1) {
      uVar10 = DAT_0010d084;
    }
    uVar10 = json_object_new_string(uVar10);
    json_object_object_add(uVar9,DAT_0010d07c,uVar10);
    uVar10 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_0010d080,uVar10);
    json_object_put(uVar9);
    qcgisess_clear(iVar4);
  }
LAB_0010c52c:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0010c54c:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

