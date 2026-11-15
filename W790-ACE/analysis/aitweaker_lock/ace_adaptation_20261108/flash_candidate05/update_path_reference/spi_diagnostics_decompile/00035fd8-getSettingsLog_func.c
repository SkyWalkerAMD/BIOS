
void getSettingsLog_func(void)

{
  bool bVar1;
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
  undefined4 local_ac;
  int local_a8;
  undefined1 local_a0;
  char local_9f;
  undefined1 local_9e;
  undefined1 local_9d;
  undefined4 local_9c;
  undefined4 local_98;
  undefined1 auStack_94 [44];
  char acStack_68 [68];
  
  iVar3 = qcgireq_parse(0);
  pcVar4 = getenv(DAT_00036990);
  pre_call_hook(iVar3);
  iVar5 = qcgisess_init(iVar3,0);
  if (iVar5 == 0) {
    FCGI_printf(DAT_000369a0);
    FCGI_printf(DAT_000369a4);
    qcgires_setcontenttype(iVar3,DAT_000369a8);
    uVar11 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar11,DAT_000369ac,uVar10);
    uVar10 = json_object_new_string(DAT_000369b0);
    json_object_object_add(uVar11,DAT_000369b4,uVar10);
    uVar10 = json_object_to_json_string(uVar11);
    FCGI_printf(DAT_000369b8,uVar10);
    json_object_put(uVar11);
    goto LAB_00036154;
  }
  iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00036994);
  if (pcVar4 == (char *)0x0 || iVar6 != 1) {
LAB_000360a4:
    FCGI_printf(DAT_000369a0);
    FCGI_printf(DAT_000369a4);
    qcgires_setcontenttype(iVar3,DAT_000369a8);
    uVar10 = json_object_new_object();
    uVar11 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_000369ac,uVar11);
    iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_0003699c);
    uVar11 = DAT_000369b0;
    if (iVar6 == 1) {
      uVar11 = DAT_000369bc;
    }
    uVar11 = json_object_new_string(uVar11);
    json_object_object_add(uVar10,DAT_000369b4,uVar11);
    uVar11 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_000369b8,uVar11);
    json_object_put(uVar10);
    qcgisess_clear(iVar5);
  }
  else {
    pcVar7 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_00036998,0);
    pcVar8 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_00036998,0);
    sVar9 = strlen(pcVar8);
    iVar6 = strncmp(pcVar7,pcVar4,sVar9);
    if ((iVar6 != 0) || (iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_0003699c), iVar6 != 0))
    goto LAB_000360a4;
    pre_authorized_call_hook(iVar3,iVar5);
    iVar6 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    local_a8 = json_object_new_object();
    pcVar4 = getenv(DAT_000369c0);
    pcVar7 = getenv(DAT_000369c4);
    if ((pcVar4 != (char *)0x0) &&
       (iVar12 = strcasecmp(pcVar4,DAT_000369c8),
       iVar12 != 0 && (pcVar7 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_a8);
      local_a8 = json_tokener_parse(__ptr);
    }
    if (*DAT_000369cc == 0) {
LAB_0003624c:
      local_9c = 0;
      local_98 = 0;
      local_9d = 0;
      memset(acStack_68,0,0x40);
      iVar12 = LIBIPMI_HL_AMIGetRemoteLogConfWithPortType
                         (auStack_94,&local_9f,&local_a0,&local_9e,acStack_68,&local_98,0x1e);
      if (iVar12 == 0) {
        if (local_9f == '\x03') {
          bVar1 = true;
LAB_000364b4:
          iVar12 = LIBIPMI_HL_AMIGetLocalLogConf(auStack_94,&local_9c,&local_9d,0x1e);
          if (iVar12 != 0) {
            IPMI_lo_Logout(auStack_94);
            if (iVar6 != 0) {
              json_object_put(iVar6);
            }
            if (__ptr != (void *)0x0) {
              free(__ptr);
            }
            if (pcVar4 == (char *)0x0) {
              local_a8 = json_object_new_object();
              uVar11 = json_object_new_string_len(DAT_00036a00,0x1d);
              json_object_object_add(local_a8,DAT_000369b4,uVar11);
              uVar11 = DAT_00036a04;
              goto LAB_00036810;
            }
            iVar6 = strcasecmp(pcVar4,DAT_000369c8);
            pcVar8 = pcVar7;
            if (pcVar7 != (char *)0x0) {
              pcVar8 = (char *)0x1;
            }
            if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
               (iVar6 = strcasecmp(pcVar4,DAT_00036a24), iVar6 == 0)) {
              strncasecmp(pcVar7,DAT_000369a8,0x10);
            }
            if (local_a8 != 0) {
              json_object_put(local_a8);
            }
            iVar6 = json_object_new_object();
            uVar11 = json_object_new_string_len(DAT_00036a00,0x1d);
            json_object_object_add(iVar6,DAT_000369b4,uVar11);
            uVar11 = json_object_new_int(DAT_00036a04);
            json_object_object_add(iVar6,DAT_00036a08,uVar11);
            FCGI_printf(DAT_00036a10,DAT_00036a0c);
            qcgires_setcontenttype(iVar3,DAT_000369a8);
            uVar11 = json_object_to_json_string(iVar6);
            FCGI_printf(DAT_000369b8,uVar11);
            if ((iVar6 != 0) && (json_object_put(iVar6), pcVar8 = pcVar7, pcVar7 != (char *)0x0)) {
              pcVar8 = (char *)0x1;
            }
            iVar6 = strcasecmp(pcVar4,DAT_000369c8);
            if (iVar6 == 0) {
              pcVar8 = (char *)0x0;
            }
            if (pcVar8 == (char *)0x0) goto LAB_00036420;
            goto joined_r0x00036854;
          }
          local_ac = 1;
        }
        else {
          if (local_9f == '\x01') {
            bVar1 = false;
            goto LAB_000364b4;
          }
          bVar1 = local_9f == '\x02';
          local_ac = 0;
        }
        uVar11 = json_object_new_int(1);
        json_object_object_add(iVar6,DAT_000369d8,uVar11);
        uVar11 = json_object_new_int(local_a0);
        json_object_object_add(iVar6,DAT_000369dc,uVar11);
        uVar11 = json_object_new_int(local_9f);
        json_object_object_add(iVar6,DAT_000369e0,uVar11);
        uVar11 = json_object_new_int(local_9e);
        json_object_object_add(iVar6,DAT_000369e4,uVar11);
        uVar11 = json_object_new_int(local_9c);
        json_object_object_add(iVar6,DAT_000369e8,uVar11);
        uVar11 = json_object_new_int(local_9d);
        json_object_object_add(iVar6,DAT_000369ec,uVar11);
        uVar11 = json_object_new_int(local_98);
        json_object_object_add(iVar6,DAT_000369f0,uVar11);
        sVar9 = strlen(acStack_68);
        uVar11 = json_object_new_string_len(acStack_68,sVar9);
        json_object_object_add(iVar6,DAT_000369f4,uVar11);
        uVar11 = json_object_new_int(bVar1);
        json_object_object_add(iVar6,DAT_000369f8,uVar11);
        uVar11 = json_object_new_int(local_ac);
        json_object_object_add(iVar6,DAT_000369fc,uVar11);
        qcgires_setcontenttype(iVar3,DAT_000369a8);
        uVar11 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_000369b8,uVar11);
        IPMI_lo_Logout(auStack_94);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 != (char *)0x0) {
          strcasecmp(pcVar4,DAT_000369c8);
          goto LAB_00036420;
        }
      }
      else {
        IPMI_lo_Logout(auStack_94);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar4 == (char *)0x0) {
          local_a8 = json_object_new_object();
          uVar11 = json_object_new_string_len(DAT_00036a00,0x1d);
          json_object_object_add(local_a8,DAT_000369b4,uVar11);
          uVar11 = DAT_00036a14;
LAB_00036810:
          uVar11 = json_object_new_int(uVar11);
          json_object_object_add(local_a8,DAT_00036a08,uVar11);
          uVar11 = DAT_00036a0c;
          goto LAB_00036828;
        }
        iVar6 = strcasecmp(pcVar4,DAT_000369c8);
        if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
           (iVar6 = strcasecmp(pcVar4,DAT_00036a24), iVar6 == 0)) {
          strncasecmp(pcVar7,DAT_000369a8,0x10);
        }
        if (local_a8 != 0) {
          json_object_put(local_a8);
        }
        iVar6 = json_object_new_object();
        uVar11 = json_object_new_string_len(DAT_00036a00,0x1d);
        json_object_object_add(iVar6,DAT_000369b4,uVar11);
        uVar11 = json_object_new_int(DAT_00036a14);
        json_object_object_add(iVar6,DAT_00036a08,uVar11);
        FCGI_printf(DAT_00036a10,DAT_00036a0c);
        qcgires_setcontenttype(iVar3,DAT_000369a8);
        uVar11 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_000369b8,uVar11);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        strcasecmp(pcVar4,DAT_000369c8);
joined_r0x00036854:
        if (local_a8 != 0) {
          json_object_put(local_a8);
        }
      }
    }
    else {
      uVar2 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_000369d0);
      iVar12 = IPMI_lo_Login(DAT_000369d4,DAT_000369d4,auStack_94,uVar2,1,0,0,0);
      if (iVar12 == 0) goto LAB_0003624c;
      IPMI_lo_Logout(auStack_94);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar4 == (char *)0x0) {
        local_a8 = json_object_new_object();
        uVar11 = json_object_new_string_len(DAT_00036a18,0x20);
        json_object_object_add(local_a8,DAT_000369b4,uVar11);
        uVar11 = json_object_new_int(DAT_00036a1c);
        json_object_object_add(local_a8,DAT_00036a08,uVar11);
        uVar11 = DAT_00036a20;
LAB_00036828:
        FCGI_printf(DAT_00036a10,uVar11);
        qcgires_setcontenttype(iVar3,DAT_000369a8);
        uVar11 = json_object_to_json_string(local_a8);
        FCGI_printf(DAT_000369b8,uVar11);
        goto joined_r0x00036854;
      }
      iVar6 = strcasecmp(pcVar4,DAT_000369c8);
      pcVar8 = pcVar7;
      if (pcVar7 != (char *)0x0) {
        pcVar8 = (char *)0x1;
      }
      if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
         (iVar6 = strcasecmp(pcVar4,DAT_00036a24), iVar6 == 0)) {
        strncasecmp(pcVar7,DAT_000369a8,0x10);
      }
      if (local_a8 != 0) {
        json_object_put(local_a8);
      }
      iVar6 = json_object_new_object();
      uVar11 = json_object_new_string_len(DAT_00036a18,0x20);
      json_object_object_add(iVar6,DAT_000369b4,uVar11);
      uVar11 = json_object_new_int(DAT_00036a1c);
      json_object_object_add(iVar6,DAT_00036a08,uVar11);
      FCGI_printf(DAT_00036a10,DAT_00036a20);
      qcgires_setcontenttype(iVar3,DAT_000369a8);
      uVar11 = json_object_to_json_string(iVar6);
      FCGI_printf(DAT_000369b8,uVar11);
      if ((iVar6 != 0) && (json_object_put(iVar6), pcVar8 = pcVar7, pcVar7 != (char *)0x0)) {
        pcVar8 = (char *)0x1;
      }
      iVar6 = strcasecmp(pcVar4,DAT_000369c8);
      if (iVar6 == 0) {
        pcVar8 = (char *)0x0;
      }
      if (pcVar8 == (char *)0x0) goto joined_r0x00036854;
LAB_00036420:
      if (local_a8 != 0) {
        json_object_put(local_a8);
      }
    }
  }
  post_authorized_call_hook(iVar3,iVar5);
  qcgisess_save(iVar5);
  (**(code **)(iVar5 + 0x58))(iVar5);
LAB_00036154:
  post_call_hook(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
  return;
}

