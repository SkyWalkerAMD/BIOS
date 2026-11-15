
void getBmcFeature_func(void)

{
  char cVar1;
  undefined1 uVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  size_t __n;
  undefined4 uVar9;
  undefined4 uVar10;
  void *__ptr;
  int iVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined1 *local_b4;
  int local_ac;
  undefined1 local_8d;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined1 local_78;
  undefined1 auStack_74 [32];
  undefined1 auStack_54 [48];
  
  iVar3 = qcgireq_parse(0);
  pcVar4 = getenv(DAT_00145e10);
  pre_call_hook(iVar3);
  iVar5 = qcgisess_init(iVar3,0);
  if (iVar5 == 0) {
    FCGI_printf(DAT_00145e20);
    FCGI_printf(DAT_00145e24);
    qcgires_setcontenttype(iVar3,DAT_00145e28);
    uVar10 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar10,DAT_00145e2c,uVar9);
    uVar9 = json_object_new_string(DAT_00145e30);
    json_object_object_add(uVar10,DAT_00145e34,uVar9);
    uVar9 = json_object_to_json_string(uVar10);
    FCGI_printf(DAT_00145e38,uVar9);
    json_object_put(uVar10);
    goto LAB_00145620;
  }
  iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00145e14);
  if (pcVar4 == (char *)0x0 || iVar6 != 1) {
LAB_00145570:
    FCGI_printf(DAT_00145e20);
    FCGI_printf(DAT_00145e24);
    qcgires_setcontenttype(iVar3,DAT_00145e28);
    uVar9 = json_object_new_object();
    uVar10 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_00145e2c,uVar10);
    iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00145e1c);
    uVar10 = DAT_00145e30;
    if (iVar6 == 1) {
      uVar10 = DAT_00145e3c;
    }
    uVar10 = json_object_new_string(uVar10);
    json_object_object_add(uVar9,DAT_00145e34,uVar10);
    uVar10 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_00145e38,uVar10);
    json_object_put(uVar9);
    qcgisess_clear(iVar5);
  }
  else {
    pcVar7 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_00145e18,0);
    pcVar8 = (char *)(**(code **)(iVar5 + 0x18))(iVar5,DAT_00145e18,0);
    __n = strlen(pcVar8);
    iVar6 = strncmp(pcVar7,pcVar4,__n);
    if ((iVar6 != 0) || (iVar6 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00145e1c), iVar6 != 0))
    goto LAB_00145570;
    pre_authorized_call_hook(iVar3,iVar5);
    iVar6 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    local_ac = json_object_new_object();
    pcVar4 = getenv(DAT_00145e40);
    pcVar7 = getenv(DAT_00145e44);
    if ((pcVar4 != (char *)0x0) &&
       (iVar11 = strcasecmp(pcVar4,DAT_00145e48),
       iVar11 != 0 && (pcVar7 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_ac);
      local_ac = json_tokener_parse(__ptr);
    }
    if (*DAT_00145e4c == 0) {
LAB_0014572c:
      local_b4 = auStack_54;
      memset(auStack_74,0,0x20);
      local_8c = 0;
      local_88 = 0;
      local_84 = 0;
      local_80 = 0;
      local_7c = 0;
      local_78 = 0;
      local_8d = 0x16;
      iVar11 = LIBIPMI_HL_GetSetFeatureList(local_b4,auStack_74,0,&local_8c,&local_8d,0x1e);
      if (iVar11 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00145ed0,DAT_00145ecc,DAT_00145ec8,iVar11);
      }
      uVar9 = json_object_new_array();
      uVar10 = DAT_00145e5c;
      pcVar8 = DAT_00145e58 + 0x1a58;
      pcVar7 = DAT_00145e58;
      do {
        if (*pcVar7 != '\0') {
          iVar11 = *(int *)(pcVar7 + 4);
          if (local_8c._1_1_ == '\x01') {
            if (DAT_00145e84 < iVar11 + 0xf4f70000U) {
              if (DAT_00145e84 < iVar11 + 0xf4f60000U) {
                if (DAT_00145e84 < iVar11 + 0xf4f80000U) goto LAB_001458dc;
                if ((local_88 & 0xff) != 0) {
                  pcVar7[8] = (char)local_88;
                  goto LAB_001457c0;
                }
              }
              else if (local_8c._3_1_ != '\0') goto LAB_00145910;
            }
            else if (local_8c._2_1_ != '\0') {
LAB_001458dc:
              if (iVar11 + 0xf4f50000U < 0x10000) {
                cVar1 = local_88._2_1_;
              }
              else {
LAB_00145910:
                if (0xffff < iVar11 + 0xf4f40000U) goto LAB_001457c0;
                cVar1 = local_88._3_1_;
              }
              if (cVar1 != '\0') goto LAB_001457c0;
            }
          }
          else if (0x2ffff < iVar11 + 0xf4f60000U) {
LAB_001457c0:
            uVar12 = json_object_new_object();
            uVar13 = json_object_new_int(iVar11);
            json_object_object_add(uVar12,DAT_00145e60,uVar13);
            uVar13 = json_object_new_int(pcVar7[8]);
            json_object_object_add(uVar12,DAT_00145e64,uVar13);
            uVar13 = json_object_new_string(*(undefined4 *)(pcVar7 + 0xc));
            json_object_object_add(uVar12,uVar10,uVar13);
            uVar13 = json_object_new_object();
            uVar14 = json_object_new_string(*(undefined4 *)(pcVar7 + 0x10));
            json_object_object_add(uVar13,DAT_00145e68,uVar14);
            uVar14 = json_object_new_string(*(undefined4 *)(pcVar7 + 0x14));
            json_object_object_add(uVar13,DAT_00145e6c,uVar14);
            json_object_object_add(uVar12,DAT_00145e70,uVar13);
            if (iVar11 == DAT_00145e74) {
              uVar14 = json_object_new_object();
              uVar15 = json_object_new_boolean(0);
              uVar13 = DAT_00145e88;
LAB_00145968:
              json_object_object_add(uVar14,uVar13,uVar15);
              json_object_object_add(uVar12,DAT_00145e8c,uVar14);
            }
            else {
              if (iVar11 == DAT_00145e78) {
                uVar14 = json_object_new_object();
                uVar13 = json_object_new_boolean(0);
                json_object_object_add(uVar14,DAT_00145e90,uVar13);
                uVar15 = json_object_new_boolean(1);
                uVar13 = DAT_00145e94;
                goto LAB_00145968;
              }
              if (iVar11 == DAT_00145e7c) {
                uVar13 = json_object_new_object();
                uVar14 = json_object_new_array();
                uVar15 = json_object_new_object();
                uVar16 = json_object_new_int(0);
                json_object_object_add(uVar15,DAT_00145e98,uVar16);
                uVar16 = json_object_new_string(DAT_00145e9c);
                json_object_object_add(uVar15,uVar10,uVar16);
                uVar16 = json_object_new_string(DAT_00145e9c);
                json_object_object_add(uVar15,DAT_00145ea0,uVar16);
                json_object_array_add(uVar14,uVar15);
                json_object_object_add(uVar13,DAT_00145ea4,uVar14);
                json_object_object_add(uVar12,DAT_00145e8c,uVar13);
              }
              else if (iVar11 == DAT_00145e80) {
                uVar14 = json_object_new_object();
                uVar15 = json_object_new_array();
                uVar13 = json_object_new_object();
                uVar16 = json_object_new_int(0);
                json_object_object_add(uVar13,DAT_00145e98,uVar16);
                uVar16 = json_object_new_string(DAT_00145ea8);
                json_object_object_add(uVar13,uVar10,uVar16);
                uVar16 = json_object_new_int(0);
                json_object_object_add(uVar13,DAT_00145ea0,uVar16);
                uVar16 = json_object_new_object();
                uVar17 = json_object_new_int(3);
                json_object_object_add(uVar16,DAT_00145e98,uVar17);
                uVar17 = json_object_new_string(DAT_00145eac);
                json_object_object_add(uVar16,uVar10,uVar17);
                uVar17 = json_object_new_int(3);
                json_object_object_add(uVar16,DAT_00145ea0,uVar17);
                json_object_array_add(uVar15,uVar13);
                json_object_array_add(uVar15,uVar16);
                uVar13 = DAT_00145ea4;
                goto LAB_00145968;
              }
            }
            json_object_array_add(uVar9,uVar12);
          }
        }
        pcVar7 = pcVar7 + 0x18;
      } while (pcVar8 != pcVar7);
      json_object_object_add(iVar6,DAT_00145eb0,uVar9);
      qcgires_setcontenttype(iVar3,DAT_00145e28);
      uVar10 = json_object_to_json_string(iVar6);
      FCGI_printf(DAT_00145e38,uVar10);
      IPMI_lo_Logout(local_b4);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar4 != (char *)0x0) {
        strcasecmp(pcVar4,DAT_00145e48);
LAB_00145ba4:
        if (local_ac != 0) {
          json_object_put(local_ac);
        }
      }
    }
    else {
      uVar2 = (**(code **)(iVar5 + 0x24))(iVar5,DAT_00145e50);
      iVar11 = IPMI_lo_Login(DAT_00145e54,DAT_00145e54,auStack_54,uVar2,1,0,0,0);
      if (iVar11 == 0) goto LAB_0014572c;
      IPMI_lo_Logout(auStack_54);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar4 != (char *)0x0) {
        iVar6 = strcasecmp(pcVar4,DAT_00145e48);
        if ((iVar6 != 0 && pcVar7 != (char *)0x0) &&
           (iVar6 = strcasecmp(pcVar4,DAT_00145ed4), iVar6 == 0)) {
          strncasecmp(pcVar7,DAT_00145e28,0x10);
        }
        if (local_ac != 0) {
          json_object_put(local_ac);
        }
        iVar6 = json_object_new_object();
        uVar10 = json_object_new_string_len(DAT_00145eb4,0x20);
        json_object_object_add(iVar6,DAT_00145e34,uVar10);
        uVar10 = json_object_new_int(DAT_00145eb8);
        json_object_object_add(iVar6,DAT_00145ebc,uVar10);
        FCGI_printf(DAT_00145ec4,DAT_00145ec0);
        qcgires_setcontenttype(iVar3,DAT_00145e28);
        uVar10 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_00145e38,uVar10);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
        strcasecmp(pcVar4,DAT_00145e48);
        goto LAB_00145ba4;
      }
      iVar6 = json_object_new_object();
      uVar10 = json_object_new_string_len(DAT_00145eb4,0x20);
      json_object_object_add(iVar6,DAT_00145e34,uVar10);
      uVar10 = json_object_new_int(DAT_00145eb8);
      json_object_object_add(iVar6,DAT_00145ebc,uVar10);
      FCGI_printf(DAT_00145ec4,DAT_00145ec0);
      qcgires_setcontenttype(iVar3,DAT_00145e28);
      uVar10 = json_object_to_json_string(iVar6);
      FCGI_printf(DAT_00145e38,uVar10);
      if (iVar6 != 0) {
        json_object_put(iVar6);
      }
    }
  }
  post_authorized_call_hook(iVar3,iVar5);
  qcgisess_save(iVar5);
  (**(code **)(iVar5 + 0x58))(iVar5);
LAB_00145620:
  post_call_hook(iVar3);
  (**(code **)(iVar3 + 0x58))(iVar3);
  return;
}

