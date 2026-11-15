
void getNtpCfg_func(void)

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
  int iVar12;
  int local_184;
  undefined4 *local_17c;
  undefined1 local_178 [4];
  undefined4 local_174;
  undefined4 local_170;
  undefined4 local_16c;
  undefined2 local_168;
  undefined1 local_166;
  undefined4 local_164;
  int local_160;
  undefined2 local_15c;
  undefined1 local_15a;
  undefined1 auStack_158 [44];
  undefined4 local_12c;
  undefined4 local_128;
  undefined4 local_124;
  undefined4 local_120;
  char acStack_aa [134];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_00085fe4);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00085ff4);
    FCGI_printf(DAT_00085ff8);
    qcgires_setcontenttype(iVar2,DAT_000860d0);
    uVar10 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_00085ffc,uVar9);
    uVar9 = json_object_new_string(DAT_00086000);
    json_object_object_add(uVar10,DAT_000860c4,uVar9);
    uVar9 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_00086004,uVar9);
    json_object_put(uVar10);
    goto LAB_00085178;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00085fe8);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00085fec,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_00085fec,0);
    sVar8 = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,sVar8);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00085ff0), iVar5 != 0))
    goto LAB_000850c8;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    local_184 = json_object_new_object();
    pcVar3 = getenv(DAT_0008600c);
    pcVar6 = getenv(DAT_00086010);
    if ((pcVar3 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar3,DAT_00086014),
       iVar11 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_184);
      local_184 = json_tokener_parse(__ptr);
    }
    if (*DAT_00086018 == 0) {
LAB_00085274:
      uVar10 = json_object_new_int(1);
      iVar11 = DAT_00086024;
      json_object_object_add(iVar5,DAT_00086028,uVar10);
      if (*(int *)(iVar11 + 0x148) != 0) {
        memset(&local_12c,0,DAT_00086084);
        iVar12 = LIBIPMI_HL_AMIGetNTPCfg(auStack_158,&local_12c,0x1e);
        if (iVar12 == 0) {
          sVar8 = strlen((char *)((int)&local_12c + 2));
          uVar10 = json_object_new_string_len((char *)((int)&local_12c + 2),sVar8);
          json_object_object_add(iVar5,DAT_00086088,uVar10);
          sVar8 = strlen(acStack_aa);
          uVar10 = json_object_new_string_len(acStack_aa,sVar8);
          json_object_object_add(iVar5,DAT_0008608c,uVar10);
          uVar10 = json_object_new_int(local_12c._1_1_);
          json_object_object_add(iVar5,DAT_00086090,uVar10);
          if (local_12c._1_1_ == '\x01') {
            *DAT_0008602c = 0;
          }
          else {
            *DAT_0008602c = 1;
          }
        }
        else {
          uVar10 = json_object_new_string_len(DAT_00086020,0);
          json_object_object_add(iVar5,DAT_00086088,uVar10);
          uVar10 = json_object_new_string_len(DAT_00086020,0);
          json_object_object_add(iVar5,DAT_0008608c,uVar10);
          uVar10 = json_object_new_int(0);
          json_object_object_add(iVar5,DAT_00086090,uVar10);
        }
      }
      if (*(int *)(iVar11 + 0x3fc) == 0) {
LAB_000854e0:
        local_17c = &local_164;
        iVar12 = IPMICMD_GetSELTime(auStack_158,local_17c,0x1e);
        if (iVar12 != 0) {
          IPMI_lo_Logout(auStack_158);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 == (char *)0x0) {
            local_184 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860b4,0x20);
            json_object_object_add(local_184,DAT_000860c4,uVar10);
            uVar10 = DAT_00086094;
LAB_00085c34:
            uVar10 = json_object_new_int(uVar10);
            json_object_object_add(local_184,DAT_00086070,uVar10);
            uVar10 = DAT_00086074;
            goto LAB_00085c4c;
          }
          iVar5 = strcasecmp(pcVar3,DAT_00086014);
          if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
             (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
            strncasecmp(pcVar6,DAT_000860d0,0x10);
          }
          if (local_184 != 0) {
            json_object_put(local_184);
          }
          iVar5 = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_000860b4,0x20);
          json_object_object_add(iVar5,DAT_000860c4,uVar10);
          uVar10 = DAT_00086094;
          goto LAB_000858f0;
        }
        uVar10 = json_object_new_int(local_160 << 0x18 | local_164 >> 8);
        json_object_object_add(iVar5,DAT_00086064,uVar10);
        if (*(int *)(iVar11 + 0x140) == 1) {
          iVar11 = IPMICMD_GetSELTimeUTCOffset(auStack_158,&local_170,0x1e);
          if (iVar11 != 0) {
            IPMI_lo_Logout(auStack_158);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 == (char *)0x0) {
              local_184 = json_object_new_object();
              uVar10 = json_object_new_string_len(DAT_000860b4,0x20);
              json_object_object_add(local_184,DAT_000860c4,uVar10);
              uVar10 = 0x3f8;
              goto LAB_00085c34;
            }
            iVar5 = strcasecmp(pcVar3,DAT_00086014);
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_000860d0,0x10);
            }
            if (local_184 != 0) {
              json_object_put(local_184);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860b4,0x20);
            json_object_object_add(iVar5,DAT_000860c4,uVar10);
            uVar10 = 0x3f8;
            goto LAB_000858f0;
          }
          uVar10 = json_object_new_int((local_170 << 8) >> 0x10);
          json_object_object_add(iVar5,DAT_00086080,uVar10);
        }
        iVar11 = GetUTC_Offset();
        uVar10 = json_object_new_int((local_160 << 0x18 | local_164 >> 8) + iVar11 * -0x3c);
        json_object_object_add(iVar5,DAT_00086068,uVar10);
        iVar11 = LIBIPMI_HL_AMIGetTimeZone(auStack_158,&local_12c,0x1e);
        if (iVar11 == 0) {
          sVar8 = strlen((char *)&local_12c);
          uVar10 = json_object_new_string_len(&local_12c,sVar8);
          json_object_object_add(iVar5,DAT_0008607c,uVar10);
          qcgires_setcontenttype(iVar2,DAT_000860d0);
          uVar10 = json_object_to_json_string(iVar5);
          FCGI_printf(DAT_00086004,uVar10);
          IPMI_lo_Logout(auStack_158);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 == (char *)0x0) goto LAB_00085158;
          strcasecmp(pcVar3,DAT_00086014);
        }
        else {
          IPMI_lo_Logout(auStack_158);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 == (char *)0x0) {
            local_184 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860b4,0x20);
            json_object_object_add(local_184,DAT_000860c4,uVar10);
            uVar10 = DAT_0008606c;
            goto LAB_00085c34;
          }
          iVar5 = strcasecmp(pcVar3,DAT_00086014);
          pcVar7 = pcVar6;
          if (pcVar6 != (char *)0x0) {
            pcVar7 = (char *)0x1;
          }
          if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
             (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
            strncasecmp(pcVar6,DAT_000860d0,0x10);
          }
          if (local_184 != 0) {
            json_object_put(local_184);
          }
          iVar5 = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_000860b4,0x20);
          json_object_object_add(iVar5,DAT_000860c4,uVar10);
          uVar10 = json_object_new_int(DAT_0008606c);
          json_object_object_add(iVar5,DAT_00086070,uVar10);
          FCGI_printf(DAT_00086078,DAT_00086074);
          qcgires_setcontenttype(iVar2,DAT_000860d0);
          uVar10 = json_object_to_json_string(iVar5);
          FCGI_printf(DAT_00086004,uVar10);
          if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
            pcVar7 = (char *)0x1;
          }
          iVar5 = strcasecmp(pcVar3,DAT_00086014);
          if (iVar5 == 0) {
            pcVar7 = (char *)0x0;
          }
          if (pcVar7 != (char *)0x0) goto LAB_00085674;
        }
LAB_00085780:
        if (local_184 != 0) {
          json_object_put(local_184);
        }
      }
      else {
        local_164 = 0;
        local_170 = 0;
        local_166 = 0;
        local_12c = 0;
        local_160 = 0;
        local_15c = 0;
        local_16c = 0;
        local_15a = 0;
        local_168 = 0;
        local_128 = 0;
        local_124 = 0;
        local_120 = 0;
        local_178[0] = 0;
        iVar12 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0008601c);
        if (iVar12 < 4) {
          uVar10 = json_object_new_int(0);
          json_object_object_add(iVar5,DAT_00086030,uVar10);
          goto LAB_000854e0;
        }
        if (*DAT_0008602c == 1) {
          local_178[0] = 3;
        }
        else {
          local_178[0] = 1;
        }
        iVar12 = LIBIPMI_HL_AMIGetPTPCfg(auStack_158,&local_170,0x1e);
        if (iVar12 != 0) {
          IPMI_lo_Logout(auStack_158);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 != (char *)0x0) {
            iVar5 = strcasecmp(pcVar3,DAT_00086014);
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_000860d0,0x10);
            }
            if (local_184 != 0) {
              json_object_put(local_184);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860a4,0x1f);
            json_object_object_add(iVar5,DAT_000860c4,uVar10);
            uVar10 = DAT_000860a8;
            goto LAB_000858f0;
          }
          local_184 = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_000860a4,0x1f);
          json_object_object_add(local_184,DAT_000860c4,uVar10);
          uVar10 = DAT_000860a8;
          goto LAB_00085c34;
        }
        iVar12 = LIBIPMI_HL_AMIGetPTPInt(auStack_158,&local_164,0x1e);
        if (iVar12 == 0) {
          iVar12 = LIBIPMI_HL_AMIGetPTPUip(auStack_158,&local_12c,0x1e);
          if (iVar12 == 0) {
            iVar12 = LIBIPMI_HL_AMIPTPCtrl(auStack_158,local_178,&local_174,0x1e);
            if (iVar12 == 0) {
              uVar10 = json_object_new_int(local_174);
              json_object_object_add(iVar5,DAT_00086030,uVar10);
              sVar8 = strlen((char *)((int)&local_164 + 1));
              uVar10 = json_object_new_string_len((char *)((int)&local_164 + 1),sVar8);
              json_object_object_add(iVar5,DAT_00086034,uVar10);
              uVar10 = json_object_new_int(local_170._1_1_);
              json_object_object_add(iVar5,DAT_00086038,uVar10);
              uVar10 = json_object_new_int(local_170._3_1_);
              json_object_object_add(iVar5,DAT_0008603c,uVar10);
              uVar10 = json_object_new_int(local_170._2_1_);
              json_object_object_add(iVar5,DAT_00086040,uVar10);
              uVar10 = json_object_new_int(local_16c & 0xff);
              json_object_object_add(iVar5,DAT_00086044,uVar10);
              uVar10 = json_object_new_int(local_16c._1_1_);
              json_object_object_add(iVar5,DAT_00086048,uVar10);
              uVar10 = json_object_new_int(local_16c._2_1_);
              json_object_object_add(iVar5,DAT_0008604c,uVar10);
              uVar10 = json_object_new_int(local_168._1_1_);
              json_object_object_add(iVar5,DAT_00086050,uVar10);
              uVar10 = json_object_new_int(local_16c._3_1_);
              json_object_object_add(iVar5,DAT_00086054,uVar10);
              uVar10 = json_object_new_int((undefined1)local_168);
              json_object_object_add(iVar5,DAT_00086058,uVar10);
              uVar10 = json_object_new_int(local_166);
              json_object_object_add(iVar5,DAT_0008605c,uVar10);
              sVar8 = strlen((char *)((int)&local_12c + 1));
              uVar10 = json_object_new_string_len((char *)((int)&local_12c + 1),sVar8);
              json_object_object_add(iVar5,DAT_00086060,uVar10);
              goto LAB_000854e0;
            }
            IPMI_lo_Logout(auStack_158);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 == (char *)0x0) {
              local_184 = json_object_new_object();
              uVar10 = json_object_new_string_len(DAT_000860c0,0x25);
              json_object_object_add(local_184,DAT_000860c4,uVar10);
              uVar10 = DAT_000860c8;
              goto LAB_00085c34;
            }
            iVar5 = strcasecmp(pcVar3,DAT_00086014);
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_000860d0,0x10);
            }
            if (local_184 != 0) {
              json_object_put(local_184);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860c0,0x25);
            json_object_object_add(iVar5,DAT_000860c4,uVar10);
            uVar10 = DAT_000860c8;
          }
          else {
            IPMI_lo_Logout(auStack_158);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 == (char *)0x0) {
              local_184 = json_object_new_object();
              uVar10 = json_object_new_string_len(DAT_000860b8,0x1b);
              json_object_object_add(local_184,DAT_000860c4,uVar10);
              uVar10 = DAT_000860bc;
              goto LAB_00085c34;
            }
            iVar5 = strcasecmp(pcVar3,DAT_00086014);
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_000860d0,0x10);
            }
            if (local_184 != 0) {
              json_object_put(local_184);
            }
            iVar5 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860b8,0x1b);
            json_object_object_add(iVar5,DAT_000860c4,uVar10);
            uVar10 = DAT_000860bc;
          }
        }
        else {
          IPMI_lo_Logout(auStack_158);
          if (iVar5 != 0) {
            json_object_put(iVar5);
          }
          if (__ptr != (void *)0x0) {
            free(__ptr);
          }
          if (pcVar3 == (char *)0x0) {
            local_184 = json_object_new_object();
            uVar10 = json_object_new_string_len(DAT_000860ac,0x1b);
            json_object_object_add(local_184,DAT_000860c4,uVar10);
            uVar10 = DAT_000860b0;
            goto LAB_00085c34;
          }
          iVar5 = strcasecmp(pcVar3,DAT_00086014);
          if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
             (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
            strncasecmp(pcVar6,DAT_000860d0,0x10);
          }
          if (local_184 != 0) {
            json_object_put(local_184);
          }
          iVar5 = json_object_new_object();
          uVar10 = json_object_new_string_len(DAT_000860ac,0x1b);
          json_object_object_add(iVar5,DAT_000860c4,uVar10);
          uVar10 = DAT_000860b0;
        }
LAB_000858f0:
        uVar10 = json_object_new_int(uVar10);
        json_object_object_add(iVar5,DAT_00086070,uVar10);
        FCGI_printf(DAT_00086078,DAT_00086074);
        qcgires_setcontenttype(iVar2,DAT_000860d0);
        uVar10 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00086004,uVar10);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_00086014);
LAB_00085674:
        if (local_184 != 0) goto LAB_00085680;
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0008601c);
      iVar11 = IPMI_lo_Login(DAT_00086020,DAT_00086020,auStack_158,uVar1,1,0,0,0);
      if (iVar11 == 0) goto LAB_00085274;
      IPMI_lo_Logout(auStack_158);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        iVar5 = strcasecmp(pcVar3,DAT_00086014);
        pcVar7 = pcVar6;
        if (pcVar6 != (char *)0x0) {
          pcVar7 = (char *)0x1;
        }
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_000860cc), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_000860d0,0x10);
        }
        if (local_184 != 0) {
          json_object_put(local_184);
        }
        iVar5 = json_object_new_object();
        uVar10 = json_object_new_string_len(DAT_00086098,0x20);
        json_object_object_add(iVar5,DAT_000860c4,uVar10);
        uVar10 = json_object_new_int(DAT_0008609c);
        json_object_object_add(iVar5,DAT_00086070,uVar10);
        FCGI_printf(DAT_00086078,DAT_000860a0);
        qcgires_setcontenttype(iVar2,DAT_000860d0);
        uVar10 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_00086004,uVar10);
        if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
          pcVar7 = (char *)0x1;
        }
        iVar5 = strcasecmp(pcVar3,DAT_00086014);
        if (iVar5 == 0) {
          pcVar7 = (char *)0x0;
        }
        if (pcVar7 != (char *)0x0) goto LAB_00085780;
        goto LAB_00085674;
      }
      local_184 = json_object_new_object();
      uVar10 = json_object_new_string_len(DAT_00086098,0x20);
      json_object_object_add(local_184,DAT_000860c4,uVar10);
      uVar10 = json_object_new_int(DAT_0008609c);
      json_object_object_add(local_184,DAT_00086070,uVar10);
      uVar10 = DAT_000860a0;
LAB_00085c4c:
      FCGI_printf(DAT_00086078,uVar10);
      qcgires_setcontenttype(iVar2,DAT_000860d0);
      uVar10 = json_object_to_json_string(local_184);
      FCGI_printf(DAT_00086004,uVar10);
      if (local_184 == 0) goto LAB_00085158;
LAB_00085680:
      json_object_put(local_184);
    }
  }
  else {
LAB_000850c8:
    FCGI_printf(DAT_00085ff4);
    FCGI_printf(DAT_00085ff8);
    qcgires_setcontenttype(iVar2,DAT_000860d0);
    uVar9 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00085ffc,uVar10);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00085ff0);
    uVar10 = DAT_00086000;
    if (iVar5 == 1) {
      uVar10 = DAT_00086008;
    }
    uVar10 = json_object_new_string(uVar10);
    json_object_object_add(uVar9,DAT_000860c4,uVar10);
    uVar10 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_00086004,uVar10);
    json_object_put(uVar9);
    qcgisess_clear(iVar4);
  }
LAB_00085158:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_00085178:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

