
void getBmcFeature_func(void)

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
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 local_b8;
  undefined1 *local_b0;
  int local_a8;
  undefined1 local_8d;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined1 local_78;
  undefined1 auStack_74 [32];
  undefined1 auStack_54 [48];
  
  iVar2 = qcgireq_parse(0);
  pcVar3 = getenv(DAT_0014c0d8);
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_0014c0e8);
    FCGI_printf(DAT_0014c0ec);
    qcgires_setcontenttype(iVar2,DAT_0014c0f0);
    uVar9 = json_object_new_object();
    uVar8 = json_object_new_int(7);
    json_object_object_add(uVar9,DAT_0014c0f4,uVar8);
    uVar8 = json_object_new_string(DAT_0014c0f8);
    json_object_object_add(uVar9,DAT_0014c0fc,uVar8);
    uVar8 = json_object_to_json_string(uVar9);
    FCGI_printf(DAT_0014c100,uVar8);
    json_object_put(uVar9);
    goto LAB_0014b7a4;
  }
  iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014c0dc);
  if (pcVar3 == (char *)0x0 || iVar5 != 1) {
LAB_0014b6f4:
    FCGI_printf(DAT_0014c0e8);
    FCGI_printf(DAT_0014c0ec);
    qcgires_setcontenttype(iVar2,DAT_0014c0f0);
    uVar8 = json_object_new_object();
    uVar9 = json_object_new_int(7);
    json_object_object_add(uVar8,DAT_0014c0f4,uVar9);
    iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014c0e4);
    uVar9 = DAT_0014c0f8;
    if (iVar5 == 1) {
      uVar9 = DAT_0014c104;
    }
    uVar9 = json_object_new_string(uVar9);
    json_object_object_add(uVar8,DAT_0014c0fc,uVar9);
    uVar9 = json_object_to_json_string(uVar8);
    FCGI_printf(DAT_0014c100,uVar9);
    json_object_put(uVar8);
    qcgisess_clear(iVar4);
  }
  else {
    pcVar6 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0014c0e0,0);
    pcVar7 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,DAT_0014c0e0,0);
    __n = strlen(pcVar7);
    iVar5 = strncmp(pcVar6,pcVar3,__n);
    if ((iVar5 != 0) || (iVar5 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014c0e4), iVar5 != 0))
    goto LAB_0014b6f4;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar5 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(4);
    local_a8 = json_object_new_object();
    pcVar3 = getenv(DAT_0014c108);
    pcVar6 = getenv(DAT_0014c10c);
    if ((pcVar3 != (char *)0x0) &&
       (iVar10 = strcasecmp(pcVar3,DAT_0014c110),
       iVar10 != 0 && (pcVar6 != (char *)0x0 && __ptr != (void *)0x0))) {
      json_object_put(local_a8);
      local_a8 = json_tokener_parse(__ptr);
    }
    if (*DAT_0014c114 == 0) {
LAB_0014b8b0:
      local_b0 = auStack_54;
      memset(auStack_74,0,0x20);
      local_8c = 0;
      local_88 = 0;
      local_84 = 0;
      local_80 = 0;
      local_7c = 0;
      local_78 = 0;
      local_8d = 0x16;
      iVar10 = LIBIPMI_HL_GetSetFeatureList(local_b0,auStack_74,0,&local_8c,&local_8d,0x1e);
      if (iVar10 != 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0014c1a8,DAT_0014c1a4,DAT_0014c1a0,iVar10);
      }
      uVar8 = json_object_new_array();
      uVar9 = DAT_0014c124;
      pcVar7 = DAT_0014c120 + 0x1a40;
      pcVar6 = DAT_0014c120;
      do {
        if ((*pcVar6 != '\0') &&
           ((local_8c._1_1_ != '\x01' ||
            ((((((local_8c._2_1_ != '\0' || (0xffff < *(int *)(pcVar6 + 4) + 0xf4f70000U)) &&
                ((local_8c._3_1_ != '\0' || (0xffff < *(int *)(pcVar6 + 4) + 0xf4f60000U)))) &&
               (((char)local_88 != '\0' || (0xffff < *(int *)(pcVar6 + 4) + 0xf4f80000U)))) &&
              ((local_88._2_1_ != '\0' || (0xffff < *(int *)(pcVar6 + 4) + 0xf4f50000U)))) &&
             ((local_88._3_1_ != '\0' || (0xffff < *(int *)(pcVar6 + 4) + 0xf4f40000U)))))))) {
          uVar11 = json_object_new_object();
          uVar12 = json_object_new_int(*(undefined4 *)(pcVar6 + 4));
          json_object_object_add(uVar11,DAT_0014c134,uVar12);
          uVar12 = json_object_new_int(pcVar6[8]);
          json_object_object_add(uVar11,DAT_0014c138,uVar12);
          uVar12 = json_object_new_string(*(undefined4 *)(pcVar6 + 0xc));
          json_object_object_add(uVar11,uVar9,uVar12);
          uVar12 = json_object_new_object();
          uVar13 = json_object_new_string(*(undefined4 *)(pcVar6 + 0x10));
          json_object_object_add(uVar12,DAT_0014c13c,uVar13);
          uVar13 = json_object_new_string(*(undefined4 *)(pcVar6 + 0x14));
          json_object_object_add(uVar12,DAT_0014c140,uVar13);
          json_object_object_add(uVar11,DAT_0014c144,uVar12);
          iVar10 = *(int *)(pcVar6 + 4);
          if (iVar10 == DAT_0014c148) {
            local_b8 = json_object_new_object();
            uVar12 = json_object_new_boolean(0);
            json_object_object_add(local_b8,DAT_0014c14c,uVar12);
            uVar13 = json_object_new_boolean(1);
            uVar12 = DAT_0014c150;
LAB_0014bb00:
            json_object_object_add(local_b8,uVar12,uVar13);
            json_object_object_add(uVar11,DAT_0014c154,local_b8);
          }
          else {
            if (iVar10 == DAT_0014c128) {
              local_b8 = json_object_new_object();
              uVar12 = json_object_new_boolean(1);
              json_object_object_add(local_b8,DAT_0014c158,uVar12);
              uVar13 = json_object_new_boolean(1);
              uVar12 = DAT_0014c15c;
              goto LAB_0014bb00;
            }
            if (iVar10 == DAT_0014c12c) {
              local_b8 = json_object_new_object();
              uVar13 = json_object_new_array();
              uVar14 = json_object_new_object();
              uVar12 = json_object_new_int(0);
              json_object_object_add(uVar14,DAT_0014c160,uVar12);
              uVar12 = json_object_new_string(DAT_0014c164);
              json_object_object_add(uVar14,uVar9,uVar12);
              uVar12 = json_object_new_string(DAT_0014c164);
              json_object_object_add(uVar14,DAT_0014c168,uVar12);
              uVar15 = json_object_new_object();
              uVar12 = json_object_new_int(1);
              json_object_object_add(uVar15,DAT_0014c160,uVar12);
              uVar12 = json_object_new_string(DAT_0014c16c);
              json_object_object_add(uVar15,uVar9,uVar12);
              uVar12 = json_object_new_string(DAT_0014c16c);
              json_object_object_add(uVar15,DAT_0014c168,uVar12);
              uVar16 = json_object_new_object();
              uVar12 = json_object_new_int(2);
              json_object_object_add(uVar16,DAT_0014c160,uVar12);
              uVar12 = json_object_new_string(DAT_0014c170);
              json_object_object_add(uVar16,uVar9,uVar12);
              uVar12 = json_object_new_string(DAT_0014c170);
              json_object_object_add(uVar16,DAT_0014c168,uVar12);
LAB_0014bc50:
              json_object_array_add(uVar13,uVar14);
              json_object_array_add(uVar13,uVar15);
              json_object_array_add(uVar13,uVar16);
              uVar12 = DAT_0014c174;
              goto LAB_0014bb00;
            }
            if (iVar10 == DAT_0014c130) {
              local_b8 = json_object_new_object();
              uVar13 = json_object_new_array();
              uVar12 = json_object_new_object();
              uVar14 = json_object_new_int(0);
              json_object_object_add(uVar12,DAT_0014c160,uVar14);
              uVar14 = json_object_new_string(DAT_0014c178);
              json_object_object_add(uVar12,uVar9,uVar14);
              uVar14 = json_object_new_int(0);
              json_object_object_add(uVar12,DAT_0014c168,uVar14);
              uVar14 = json_object_new_object();
              uVar15 = json_object_new_int(1);
              json_object_object_add(uVar14,DAT_0014c160,uVar15);
              uVar15 = json_object_new_string(DAT_0014c17c);
              json_object_object_add(uVar14,uVar9,uVar15);
              uVar15 = json_object_new_int(1);
              json_object_object_add(uVar14,DAT_0014c168,uVar15);
              uVar15 = json_object_new_object();
              uVar16 = json_object_new_int(2);
              json_object_object_add(uVar15,DAT_0014c160,uVar16);
              uVar16 = json_object_new_string(DAT_0014c180);
              json_object_object_add(uVar15,uVar9,uVar16);
              uVar16 = json_object_new_int(2);
              json_object_object_add(uVar15,DAT_0014c168,uVar16);
              uVar16 = json_object_new_object();
              uVar17 = json_object_new_int(3);
              json_object_object_add(uVar16,DAT_0014c160,uVar17);
              uVar17 = json_object_new_string(DAT_0014c184);
              json_object_object_add(uVar16,uVar9,uVar17);
              uVar17 = json_object_new_int(3);
              json_object_object_add(uVar16,DAT_0014c168,uVar17);
              json_object_array_add(uVar13,uVar12);
              goto LAB_0014bc50;
            }
          }
          json_object_array_add(uVar8,uVar11);
        }
        pcVar6 = pcVar6 + 0x18;
      } while (pcVar7 != pcVar6);
      json_object_object_add(iVar5,DAT_0014c188,uVar8);
      qcgires_setcontenttype(iVar2,DAT_0014c0f0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0014c100,uVar9);
      IPMI_lo_Logout(local_b0);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        strcasecmp(pcVar3,DAT_0014c110);
LAB_0014be6c:
        if (local_a8 != 0) {
          json_object_put(local_a8);
        }
      }
    }
    else {
      uVar1 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_0014c118);
      iVar10 = IPMI_lo_Login(DAT_0014c11c,DAT_0014c11c,auStack_54,uVar1,1,0,0,0);
      if (iVar10 == 0) goto LAB_0014b8b0;
      IPMI_lo_Logout(auStack_54);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
      if (__ptr != (void *)0x0) {
        free(__ptr);
      }
      if (pcVar3 != (char *)0x0) {
        iVar5 = strcasecmp(pcVar3,DAT_0014c110);
        if ((iVar5 != 0 && pcVar6 != (char *)0x0) &&
           (iVar5 = strcasecmp(pcVar3,DAT_0014c1ac), iVar5 == 0)) {
          strncasecmp(pcVar6,DAT_0014c0f0,0x10);
        }
        if (local_a8 != 0) {
          json_object_put(local_a8);
        }
        iVar5 = json_object_new_object();
        uVar9 = json_object_new_string_len(DAT_0014c18c,0x20);
        json_object_object_add(iVar5,DAT_0014c0fc,uVar9);
        uVar9 = json_object_new_int(DAT_0014c190);
        json_object_object_add(iVar5,DAT_0014c194,uVar9);
        FCGI_printf(DAT_0014c19c,DAT_0014c198);
        qcgires_setcontenttype(iVar2,DAT_0014c0f0);
        uVar9 = json_object_to_json_string(iVar5);
        FCGI_printf(DAT_0014c100,uVar9);
        if (iVar5 != 0) {
          json_object_put(iVar5);
        }
        strcasecmp(pcVar3,DAT_0014c110);
        goto LAB_0014be6c;
      }
      iVar5 = json_object_new_object();
      uVar9 = json_object_new_string_len(DAT_0014c18c,0x20);
      json_object_object_add(iVar5,DAT_0014c0fc,uVar9);
      uVar9 = json_object_new_int(DAT_0014c190);
      json_object_object_add(iVar5,DAT_0014c194,uVar9);
      FCGI_printf(DAT_0014c19c,DAT_0014c198);
      qcgires_setcontenttype(iVar2,DAT_0014c0f0);
      uVar9 = json_object_to_json_string(iVar5);
      FCGI_printf(DAT_0014c100,uVar9);
      if (iVar5 != 0) {
        json_object_put(iVar5);
      }
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_0014b7a4:
  post_call_hook(iVar2);
  (**(code **)(iVar2 + 0x58))(iVar2);
  return;
}

