
void getBackupConfig_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  size_t __n;
  undefined4 uVar8;
  undefined4 uVar9;
  void *__ptr;
  int iVar10;
  uint uVar11;
  uint uVar12;
  char cVar13;
  int local_b8;
  byte local_a9;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined1 auStack_98 [44];
  undefined1 auStack_6c [66];
  undefined2 local_2a;
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_000e01a8);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_000e01b8);
    FCGI_printf(DAT_000e01bc);
    qcgires_setcontenttype(iVar2,DAT_000e01c0);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_000e01c4,uVar8);
    uVar8 = json_object_new_string(DAT_000e01c8);
    json_object_object_add(uVar9,DAT_000e01cc,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_000e01d0,uVar8);
    json_object_put(uVar9);
    goto LAB_000df808;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e01ac);
  if (iVar5 == 1 && pcVar3 != (char *)0x0) {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e01b0,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_000e01b0,0);
    __n = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e01b4), iVar5 != 0))
    goto LAB_000df758;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    local_b8 = json_object_new_object();
    pcVar3 = getenv(DAT_000e01d8);
    pcVar6 = getenv(DAT_000e01dc);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_000e01e0),
       iVar10 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_b8);
      local_b8 = json_tokener_parse(__ptr);
    }
    if (*DAT_000e01e4 == 0) {
LAB_000df8fc:
      local_a9 = 0;
      local_a8 = 0;
      local_a4 = 0;
      local_a0 = 0;
      local_9c = 0;
      if (*(int *)(DAT_000e01f0 + 0x30c) != 1) {
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 == (char *)0x0) {
          local_b8 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000e01f4,0x16);
          json_object_object_add(local_b8,DAT_000e01cc,uVar9);
          uVar9 = json_object_new_int(DAT_000e01f8);
          json_object_object_add(local_b8,DAT_000e01fc,uVar9);
          uVar9 = DAT_000e0200;
          goto LAB_000dfd34;
        }
        iVar5 = strcasecmp(pcVar3,DAT_000e01e0);
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_000e0208), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_000e01c0,0x10);
        }
        if (local_b8 != 0) {
          json_object_put(local_b8);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e01f4,0x16);
        json_object_object_add(iVar5,DAT_000e01cc,uVar9);
        uVar9 = json_object_new_int(DAT_000e01f8);
        json_object_object_add(iVar5,DAT_000e01fc,uVar9);
        uVar9 = DAT_000e0200;
LAB_000df9b8:
        FCGI_printf(DAT_000e0204,uVar9);
        qcgires_setcontenttype(iVar2,DAT_000e01c0);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_000e01d0,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_000e01e0);
        goto LAB_000df9fc;
      }
      uVar9 = json_object_new_int();
      json_object_object_add(iVar5,DAT_000e020c,uVar9);
      iVar10 = LIBIPMI_HL_AMIGetBackupFlag(auStack_98,&local_a9,&local_a8,0x1e);
      if (iVar10 != 0) {
        IPMI_lo_Logout(auStack_98);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 != (char *)0x0) {
          iVar5 = strcasecmp(pcVar3,DAT_000e01e0);
          if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
             (iVar5 = strcasecmp(pcVar3,DAT_000e0208), iVar5 == 0)) {
            strncasecmp(pcVar6,DAT_000e01c0,0x10);
          }
          if (local_b8 != 0) {
            json_object_put(local_b8);
          }
          iVar5 = json_object_new_object();
          uVar9 = json_object_new_string_len(DAT_000e0230,0x25);
          json_object_object_add(iVar5,DAT_000e01cc,uVar9);
          uVar9 = json_object_new_int(DAT_000e0248);
          json_object_object_add(iVar5,DAT_000e01fc,uVar9);
          uVar9 = DAT_000e0238;
          goto LAB_000df9b8;
        }
        local_b8 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e0230,0x25);
        json_object_object_add(local_b8,DAT_000e01cc,uVar9);
        uVar9 = DAT_000e0248;
LAB_000e005c:
        uVar9 = json_object_new_int(uVar9);
        json_object_object_add(local_b8,DAT_000e01fc,uVar9);
        uVar9 = DAT_000e0238;
LAB_000dfd34:
        FCGI_printf(DAT_000e0204,uVar9);
        qcgires_setcontenttype(iVar2,DAT_000e01c0);
        uVar9 = json_object_to_json_string(local_b8);
        FCGI_printf(DAT_000e01d0,uVar9);
        if (local_b8 == 0) goto LAB_000df7e8;
        goto LAB_000dfa08;
      }
      cVar13 = *(int *)(DAT_000e01f0 + 100) != 1;
      if (local_a9 != 0) {
        uVar11 = 0;
        uVar12 = 0;
        do {
          memset(auStack_6c,0,0x44);
          iVar10 = LIBIPMI_HL_AMIGetBackupList
                             (auStack_98,*(undefined1 *)((int)&local_a8 + uVar12),auStack_6c,0x1e);
          if (iVar10 != 0) {
            IPMI_lo_Logout(auStack_98);
            if (iVar5 != 0) {
              json_object_put(iVar5);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar3 == (char *)0x0) {
              local_b8 = json_object_new_object();
              uVar9 = json_object_new_string_len(DAT_000e0230,0x25);
              json_object_object_add(local_b8,DAT_000e01cc,uVar9);
              uVar9 = DAT_000e0234;
              goto LAB_000e005c;
            }
            iVar5 = strcasecmp(pcVar3,DAT_000e01e0);
            pcVar7 = pcVar6;
            if (pcVar6 != (char *)0x0) {
              pcVar7 = (char *)0x1;
            }
            if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
               (iVar5 = strcasecmp(pcVar3,DAT_000e0208), iVar5 == 0)) {
              strncasecmp(pcVar6,DAT_000e01c0,0x10);
            }
            if (local_b8 != 0) {
              json_object_put(local_b8);
            }
            iVar5 = json_object_new_object();
            uVar9 = json_object_new_string_len(DAT_000e0230,0x25);
            json_object_object_add(iVar5,DAT_000e01cc,uVar9);
            uVar9 = json_object_new_int(DAT_000e0234);
            json_object_object_add(iVar5,DAT_000e01fc,uVar9);
            FCGI_printf(DAT_000e0204,DAT_000e0238);
            qcgires_setcontenttype(iVar2,DAT_000e01c0);
            uVar9 = json_object_to_json_string(iVar5);
            FCGI_printf(DAT_000e01d0,uVar9);
            if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
              pcVar7 = (char *)0x1;
            }
            iVar5 = strcasecmp(pcVar3,DAT_000e01e0);
            if (iVar5 == 0) {
              pcVar7 = (char *)0x0;
            }
            if (pcVar7 != (char *)0x0) goto LAB_000df9fc;
            goto LAB_000dfc08;
          }
          switch(cVar13) {
          case '\0':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e021c,uVar9);
            break;
          case '\x01':
            if (*(int *)(DAT_000e01f0 + 0x3f8) != 0) {
              uVar9 = json_object_new_int(local_2a);
              json_object_object_add(iVar5,DAT_000e022c,uVar9);
            }
            break;
          case '\x02':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e0228,uVar9);
            break;
          case '\x03':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e0224,uVar9);
            break;
          case '\x04':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e0220,uVar9);
            break;
          case '\x05':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e0218,uVar9);
            break;
          case '\x06':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e0214,uVar9);
            break;
          case '\a':
            uVar9 = json_object_new_int(local_2a);
            json_object_object_add(iVar5,DAT_000e0210,uVar9);
          }
          uVar11 = uVar11 + 1;
          uVar12 = uVar11 & 0xff;
          cVar13 = cVar13 + '\x01';
        } while (uVar12 < local_a9);
      }
      qcgires_setcontenttype(iVar2,DAT_000e01c0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_000e01d0,uVar9);
      IPMI_lo_Logout(auStack_98);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_000e01e0);
        goto LAB_000dfc08;
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e01e8);
      iVar10 = IPMI_lo_Login(DAT_000e01ec,DAT_000e01ec,auStack_98,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_000df8fc;
      IPMI_lo_Logout(auStack_98);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 == (char *)0x0) {
        local_b8 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_000e023c,0x20);
        json_object_object_add(local_b8,DAT_000e01cc,uVar9);
        uVar9 = json_object_new_int(DAT_000e0240);
        json_object_object_add(local_b8,DAT_000e01fc,uVar9);
        uVar9 = DAT_000e0244;
        goto LAB_000dfd34;
      }
      iVar5 = strcasecmp(pcVar3,DAT_000e01e0);
      pcVar7 = pcVar6;
      if (pcVar6 != (char *)0x0) {
        pcVar7 = (char *)0x1;
      }
      if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
         (iVar5 = strcasecmp(pcVar3,DAT_000e0208), iVar5 == 0)) {
        strncasecmp(pcVar6,DAT_000e01c0,0x10);
      }
      if (local_b8 != 0) {
        json_object_put(local_b8);
      }
      iVar5 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_000e023c,0x20);
      json_object_object_add(iVar5,DAT_000e01cc,uVar9);
      uVar9 = json_object_new_int(DAT_000e0240);
      json_object_object_add(iVar5,DAT_000e01fc,uVar9);
      FCGI_printf(DAT_000e0204,DAT_000e0244);
      qcgires_setcontenttype(iVar2,DAT_000e01c0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_000e01d0,uVar9);
      if ((iVar5 != 0) && (json_object_put(iVar5), pcVar7 = pcVar6, pcVar6 != (char *)0x0)) {
        pcVar7 = (char *)0x1;
      }
      iVar5 = strcasecmp(pcVar3,DAT_000e01e0);
      if (iVar5 == 0) {
        pcVar7 = (char *)0x0;
      }
      if (pcVar7 != (char *)0x0) {
LAB_000dfc08:
        if (local_b8 != 0) {
          json_object_put(local_b8);
        }
        goto LAB_000df7e8;
      }
LAB_000df9fc:
      if (local_b8 != 0) {
LAB_000dfa08:
        json_object_put(local_b8);
      }
    }
  }
  else {
LAB_000df758:
    FCGI_printf(DAT_000e01b8);
    FCGI_printf(DAT_000e01bc);
    qcgires_setcontenttype(iVar2,DAT_000e01c0);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_000e01c4,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_000e01b4);
    uVar9 = DAT_000e01c8;
    if (iVar5 == 1) {
      uVar9 = DAT_000e01d4;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_000e01cc,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_000e01d0,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
LAB_000df7e8:
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_000df808:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

