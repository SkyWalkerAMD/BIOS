
void setBIOSPrepareComponents_func(void)

{
  undefined1 uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  size_t sVar8;
  char *pcVar9;
  size_t sVar10;
  char *pcVar11;
  void *__ptr;
  int iVar12;
  undefined4 uVar13;
  int iVar14;
  uint uVar15;
  undefined4 uVar16;
  uint uVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  undefined1 uStack_1005d;
  undefined4 uStack_1005c;
  undefined1 auStack_10058 [4];
  int iStack_10054;
  
  iVar18 = DAT_00201f60 + 0x201214;
  uVar17 = **(uint **)(DAT_00201f5c + 0x201210 + DAT_00201f64);
  iVar2 = qcgireq_parse(0,0,0);
  pcVar3 = getenv((char *)(DAT_00201f68 + 0x201248));
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00201f6c + 0x201274);
    FCGI_printf(DAT_00201f70 + 0x201280);
    qcgires_setcontenttype(iVar2,DAT_00201f74 + 0x201290);
    iVar4 = json_object_new_object();
    uVar5 = json_object_new_int(7);
    json_object_object_add(iVar4,DAT_00201f78 + 0x2012b4,uVar5);
    uVar5 = json_object_new_string(DAT_00201f7c + 0x2012c0);
    json_object_object_add(iVar4,DAT_00201f80 + 0x2012d4,uVar5);
    uVar5 = json_object_to_json_string(iVar4);
    FCGI_printf(DAT_00201f84 + 0x2012ec,uVar5);
    if (iVar4 != 0) {
      json_object_put(iVar4);
    }
    goto LAB_002012fc;
  }
  iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201f90 + 0x20136c);
  if (pcVar3 == (char *)0x0 || iVar6 != 1) {
LAB_00201384:
    FCGI_printf(DAT_00201f94 + 0x201390);
    FCGI_printf(DAT_00201f98 + 0x20139c);
    qcgires_setcontenttype(iVar2,DAT_00201f9c + 0x2013ac);
    iVar6 = json_object_new_object();
    uVar5 = json_object_new_int(7);
    json_object_object_add(iVar6,DAT_00201fa0 + 0x2013d0,uVar5);
    iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201fa4 + 0x2013e4);
    if (iVar7 == 1) {
      uVar5 = json_object_new_string(DAT_00201fa8 + 0x2013f8);
      iVar7 = DAT_00201fac + 0x201408;
    }
    else {
      iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201fec + 0x2016b4);
      if ((iVar7 == 1) &&
         (iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201ff0 + 0x2016d0), iVar7 == 0)) {
        uVar5 = json_object_new_string(DAT_00201ff4 + 0x2016e4);
        iVar7 = DAT_00201ff8 + 0x2016f4;
      }
      else {
        uVar5 = json_object_new_string(DAT_00201ffc + 0x201700);
        iVar7 = DAT_00202000 + 0x201710;
      }
    }
    json_object_object_add(iVar6,iVar7,uVar5);
    uVar5 = json_object_to_json_string(iVar6);
    FCGI_printf(DAT_00201fb0 + 0x201424,uVar5);
    if (iVar6 != 0) {
      json_object_put(iVar6);
    }
    qcgisess_clear(iVar4);
  }
  else {
    sVar8 = strlen(pcVar3);
    iVar6 = DAT_00201fb4 + 0x201480;
    pcVar9 = (char *)(**(code **)(iVar4 + 0x18))(iVar4);
    sVar10 = strlen(pcVar9);
    if (sVar8 != sVar10) goto LAB_00201384;
    pcVar9 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,iVar6,0);
    pcVar11 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,iVar6,0);
    sVar8 = strlen(pcVar11);
    iVar6 = strncmp(pcVar9,pcVar3,sVar8);
    if (((iVar6 != 0) ||
        (iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201fb8 + 0x2014f8), iVar6 != 0)) ||
       ((iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201fbc + 0x201514), iVar6 == 1 &&
        (iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00201fc0 + 0x201530), iVar6 == 0))))
    goto LAB_00201384;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar7 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar6 = json_object_new_object();
    uStack_1005c = 0;
    pcVar3 = getenv((char *)(DAT_00201fc4 + 0x201578));
    pcVar9 = getenv((char *)(DAT_00201fc8 + 0x201588));
    if (pcVar3 == (char *)0x0) {
LAB_00201724:
      uStack_1005d = 1;
      iVar12 = FCGI_fopen(DAT_00202008 + 0x201740,DAT_00202004 + 0x201738);
      if (iVar12 != 0) {
        FCGI_fwrite(&uStack_1005d,1);
      }
      unlink((char *)(DAT_0020200c + 0x201768));
      iVar19 = DAT_00202010 + 0x201780;
      iVar14 = json_object_object_get_ex(iVar6,iVar19,&uStack_1005c);
      iVar22 = iVar6;
      if (iVar14 == 0) {
        FCGI_printf(DAT_00202064 + 0x2019c0);
        qcgires_setcontenttype(iVar2,DAT_00202068 + 0x2019d0);
        uVar5 = json_object_new_object();
        uVar13 = json_object_new_int(8);
        json_object_object_add(uVar5,DAT_0020206c + 0x2019f4,uVar13);
        uVar13 = json_object_new_string(DAT_00202070 + 0x201a00);
        json_object_object_add(uVar5,DAT_00202074 + 0x201a14,uVar13);
        uVar13 = json_object_to_json_string(uVar5);
        iVar6 = DAT_00202078 + 0x201a2c;
LAB_00201984:
        FCGI_printf(iVar6,uVar13);
        json_object_put(uVar5);
LAB_00201990:
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
      }
      else {
        iVar14 = json_object_get_type(uStack_1005c);
        if (iVar14 != 3) {
          FCGI_printf(DAT_0020204c + 0x20191c);
          qcgires_setcontenttype(iVar2,DAT_00202050 + 0x20192c);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_00202054 + 0x201950,uVar13);
          uVar13 = json_object_new_string(DAT_00202058 + 0x20195c);
          json_object_object_add(uVar5,DAT_0020205c + 0x201970,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00202060 + 0x201988;
          goto LAB_00201984;
        }
        uVar15 = json_object_get_int64(uStack_1005c);
        iVar20 = DAT_00202014 + 0x2017c0;
        iVar14 = json_object_object_get_ex(iVar6,iVar20,&uStack_1005c);
        if (iVar14 == 0) {
          FCGI_printf(DAT_00202018 + 0x2017e0);
          qcgires_setcontenttype(iVar2,DAT_0020201c + 0x2017f0);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_00202020 + 0x201814,uVar13);
          uVar13 = json_object_new_string(DAT_00202024 + 0x201820);
          json_object_object_add(uVar5,DAT_00202028 + 0x201834,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_0020202c + 0x20184c;
          goto LAB_00201984;
        }
        iVar14 = json_object_get_type(uStack_1005c);
        if (iVar14 != 3) {
          FCGI_printf(DAT_00202098 + 0x201af0);
          qcgires_setcontenttype(iVar2,DAT_0020209c + 0x201b00);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002020a0 + 0x201b24,uVar13);
          uVar13 = json_object_new_string(DAT_002020a4 + 0x201b30);
          json_object_object_add(uVar5,DAT_002020a8 + 0x201b44,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_002020ac + 0x201b5c;
          goto LAB_00201984;
        }
        uVar5 = json_object_get_int64(uStack_1005c);
        iVar21 = DAT_0020207c + 0x201a58;
        iVar14 = json_object_object_get_ex(iVar6,iVar21,&uStack_1005c);
        if (iVar14 == 0) {
          FCGI_printf(DAT_00202080 + 0x201a78);
          qcgires_setcontenttype(iVar2,DAT_00202084 + 0x201a88);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_00202088 + 0x201aac,uVar13);
          uVar13 = json_object_new_string(DAT_0020208c + 0x201ab8);
          json_object_object_add(uVar5,DAT_00202090 + 0x201acc,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00202094 + 0x201ae4;
          goto LAB_00201984;
        }
        iVar14 = json_object_get_type(uStack_1005c);
        if (iVar14 != 3) {
          FCGI_printf(DAT_002020cc + 0x201c18);
          qcgires_setcontenttype(iVar2,DAT_002020d0 + 0x201c28);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002020d4 + 0x201c4c,uVar13);
          uVar13 = json_object_new_string(DAT_002020d8 + 0x201c58);
          json_object_object_add(uVar5,DAT_002020dc + 0x201c6c,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_002020e0 + 0x201c84;
          goto LAB_00201984;
        }
        uVar13 = json_object_get_int64(uStack_1005c);
        iVar14 = json_object_object_get_ex(iVar6,DAT_002020b0 + 0x201b88,&uStack_1005c);
        if (iVar14 == 0) {
          FCGI_printf(DAT_002020b4 + 0x201ba0);
          qcgires_setcontenttype(iVar2,DAT_002020b8 + 0x201bb0);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002020bc + 0x201bd4,uVar13);
          uVar13 = json_object_new_string(DAT_002020c0 + 0x201be0);
          json_object_object_add(uVar5,DAT_002020c4 + 0x201bf4,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_002020c8 + 0x201c0c;
          goto LAB_00201984;
        }
        iVar14 = json_object_get_type(uStack_1005c);
        if (iVar14 != 3) {
          FCGI_printf(DAT_002020ec + 0x201d64);
          qcgires_setcontenttype(iVar2,DAT_002020f0 + 0x201d74);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002020f4 + 0x201d98,uVar13);
          uVar13 = json_object_new_string(DAT_002020f8 + 0x201da4);
          json_object_object_add(uVar5,DAT_002020fc + 0x201db8,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00202100 + 0x201dd0;
          goto LAB_00201984;
        }
        uVar1 = json_object_get_int64(uStack_1005c);
        CMD_Prepare_FW_Update(auStack_10058,uVar13,uVar15 & 0xff,uVar5,uVar1,0,1);
        uVar16 = json_object_new_int(uVar15);
        json_object_object_add(iVar7,iVar19,uVar16);
        uVar5 = json_object_new_int(uVar5);
        json_object_object_add(iVar7,iVar20,uVar5);
        uVar5 = json_object_new_int(uVar13);
        json_object_object_add(iVar7,iVar21,uVar5);
        if (iStack_10054 == 0) {
          if (iVar12 != 0) {
            FCGI_fclose(iVar12);
          }
          qcgires_setcontenttype(iVar2,DAT_002020e4 + 0x201d3c);
          uVar5 = json_object_to_json_string(iVar7);
          FCGI_printf(DAT_002020e8 + 0x201d54,uVar5);
          goto LAB_00201990;
        }
        if (iVar12 != 0) {
          uStack_1005d = 0;
          FCGI_fwrite(&uStack_1005d,1,1,iVar12);
          FCGI_fclose(iVar12);
        }
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 != (char *)0x0) {
          iVar7 = strcasecmp(pcVar3,(char *)(DAT_00202104 + 0x201e38));
          if ((iVar7 == 0 || pcVar9 == (char *)0x0) ||
             ((iVar7 = strcasecmp(pcVar3,(char *)(DAT_00202108 + 0x201e5c)), iVar7 == 0 &&
              (iVar7 = strncasecmp(pcVar9,(char *)(DAT_0020210c + 0x201e78),0x10), iVar7 == 0)))) {
            if (iVar6 != 0) {
              json_object_put(iVar6);
              iVar22 = 0;
            }
          }
          else if (iVar6 != 0) {
            iVar22 = 0;
            json_object_put(iVar6);
          }
        }
        iVar6 = json_object_new_object();
        uVar5 = json_object_new_string_len(DAT_00202110 + 0x201ec4,0x1f);
        json_object_object_add(iVar6,DAT_00202114 + 0x201ed8,uVar5);
        uVar5 = json_object_new_int(0x5a2);
        json_object_object_add(iVar6,DAT_00202118 + 0x201ef4,uVar5);
        FCGI_printf(DAT_00202120 + 0x201f08,DAT_0020211c + 0x201f04);
        qcgires_setcontenttype(iVar2,DAT_00202124 + 0x201f18);
        uVar5 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_00202128 + 0x201f30,uVar5);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
      }
      iVar6 = iVar22;
      if (pcVar3 != (char *)0x0) {
LAB_002018fc:
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
      }
    }
    else {
      iVar12 = strcasecmp(pcVar3,(char *)(DAT_00201fcc + 0x2015a4));
      if (__ptr == (void *)0x0 || iVar12 == 0) {
        iVar12 = strcasecmp(pcVar3,(char *)(DAT_00202030 + 0x20185c));
        if (__ptr != (void *)0x0 || iVar12 != 0) goto LAB_00201724;
        json_object_put(iVar6);
        FCGI_printf(DAT_00202034 + 0x201878);
        qcgires_setcontenttype(iVar2,DAT_00202038 + 0x201888);
        uVar5 = json_object_new_object();
        uVar13 = json_object_new_int(8);
        json_object_object_add(uVar5,DAT_0020203c + 0x2018ac,uVar13);
        uVar13 = json_object_new_string(DAT_00202040 + 0x2018b8);
        json_object_object_add(uVar5,DAT_00202044 + 0x2018cc,uVar13);
        uVar13 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_00202048 + 0x2018e4,uVar13);
        json_object_put(uVar5);
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        goto LAB_002018fc;
      }
      if (pcVar9 == (char *)0x0) goto LAB_00201724;
      iVar12 = strcasecmp(pcVar3,(char *)(DAT_00201fd0 + 0x2015c8));
      if (iVar12 != 0) {
LAB_00201710:
        json_object_put(iVar6);
        iVar6 = json_tokener_parse(__ptr);
        goto LAB_00201724;
      }
      pcVar11 = (char *)(DAT_00201fd4 + 0x2015e4);
      iVar12 = strncasecmp(pcVar9,pcVar11,0x10);
      if (iVar12 != 0) goto LAB_00201710;
      json_object_put(iVar6);
      iVar6 = json_tokener_parse(__ptr);
      if (iVar6 != 0) goto LAB_00201724;
      FCGI_printf(DAT_00201fd8 + 0x201614);
      qcgires_setcontenttype(iVar2,pcVar11);
      uVar5 = json_object_new_object();
      uVar13 = json_object_new_int(8);
      json_object_object_add(uVar5,DAT_00201fdc + 0x201644,uVar13);
      uVar13 = json_object_new_string(DAT_00201fe0 + 0x201650);
      json_object_object_add(uVar5,DAT_00201fe4 + 0x201664,uVar13);
      uVar13 = json_object_to_json_string(uVar5);
      FCGI_printf(DAT_00201fe8 + 0x20167c,uVar13);
      json_object_put(uVar5);
      if (iVar7 != 0) {
        json_object_put(iVar7);
      }
      free(__ptr);
    }
  }
  post_authorized_call_hook(iVar2,iVar4);
  qcgisess_save(iVar4);
  (**(code **)(iVar4 + 0x58))(iVar4);
LAB_002012fc:
  post_call_hook(iVar2);
  if (iVar2 != 0) {
    (**(code **)(iVar2 + 0x58))(iVar2);
  }
  uVar5 = FCGI_fflush(*(int *)(iVar18 + DAT_00201f88) + 8);
  uVar17 = uVar17 ^ **(uint **)(DAT_00201f8c + 0x201340 + DAT_00201f64);
  if (uVar17 == 0) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar5,uVar17,0);
}

