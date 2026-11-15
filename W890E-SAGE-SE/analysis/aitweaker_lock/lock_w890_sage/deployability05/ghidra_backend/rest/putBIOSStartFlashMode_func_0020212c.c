
/* WARNING: Restarted to delay deadcode elimination for space: stack */

void putBIOSStartFlashMode_func(void)

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
  undefined4 uVar15;
  undefined4 uVar16;
  uint uVar17;
  int iVar18;
  undefined4 uStack_10044;
  undefined1 auStack_10040 [4];
  int iStack_1003c;
  
  iVar18 = DAT_00202f70 + 0x202154;
  uVar17 = **(uint **)(DAT_00202f6c + 0x202150 + DAT_00202f74);
  iVar2 = qcgireq_parse(0,0,0);
  pcVar3 = getenv((char *)(DAT_00202f78 + 0x202188));
  pre_call_hook(iVar2);
  iVar4 = qcgisess_init(iVar2,0);
  if (iVar4 == 0) {
    FCGI_printf(DAT_00202f7c + 0x2021b4);
    FCGI_printf(DAT_00202f80 + 0x2021c0);
    qcgires_setcontenttype(iVar2,DAT_00202f84 + 0x2021d0);
    iVar4 = json_object_new_object();
    uVar5 = json_object_new_int(7);
    json_object_object_add(iVar4,DAT_00202f88 + 0x2021f4,uVar5);
    uVar5 = json_object_new_string(DAT_00202f8c + 0x202200);
    json_object_object_add(iVar4,DAT_00202f90 + 0x202214,uVar5);
    uVar5 = json_object_to_json_string(iVar4);
    FCGI_printf(DAT_00202f94 + 0x20222c,uVar5);
    if (iVar4 != 0) {
      json_object_put(iVar4);
    }
    goto LAB_0020223c;
  }
  iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00202fa0 + 0x2022ac);
  if (pcVar3 == (char *)0x0 || iVar6 != 1) {
LAB_002022c4:
    FCGI_printf(DAT_00202fa4 + 0x2022d0);
    FCGI_printf(DAT_00202fa8 + 0x2022dc);
    qcgires_setcontenttype(iVar2,DAT_00202fac + 0x2022ec);
    iVar6 = json_object_new_object();
    uVar5 = json_object_new_int(7);
    json_object_object_add(iVar6,DAT_00202fb0 + 0x202310,uVar5);
    iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00202fb4 + 0x202324);
    if (iVar7 == 1) {
      uVar5 = json_object_new_string(DAT_00202fb8 + 0x202338);
      iVar7 = DAT_00202fbc + 0x202348;
    }
    else {
      iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00202ffc + 0x2025fc);
      if ((iVar7 == 1) &&
         (iVar7 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00203000 + 0x202618), iVar7 == 0)) {
        uVar5 = json_object_new_string(DAT_00203004 + 0x20262c);
        iVar7 = DAT_00203008 + 0x20263c;
      }
      else {
        uVar5 = json_object_new_string(DAT_0020300c + 0x202648);
        iVar7 = DAT_00203010 + 0x202658;
      }
    }
    json_object_object_add(iVar6,iVar7,uVar5);
    uVar5 = json_object_to_json_string(iVar6);
    FCGI_printf(DAT_00202fc0 + 0x202364,uVar5);
    if (iVar6 != 0) {
      json_object_put(iVar6);
    }
    qcgisess_clear(iVar4);
  }
  else {
    sVar8 = strlen(pcVar3);
    iVar6 = DAT_00202fc4 + 0x2023c0;
    pcVar9 = (char *)(**(code **)(iVar4 + 0x18))(iVar4);
    sVar10 = strlen(pcVar9);
    if (sVar8 != sVar10) goto LAB_002022c4;
    pcVar9 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,iVar6,0);
    pcVar11 = (char *)(**(code **)(iVar4 + 0x18))(iVar4,iVar6,0);
    sVar8 = strlen(pcVar11);
    iVar6 = strncmp(pcVar9,pcVar3,sVar8);
    if (((iVar6 != 0) ||
        (iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00202fc8 + 0x202438), iVar6 != 0)) ||
       ((iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00202fcc + 0x202454), iVar6 == 1 &&
        (iVar6 = (**(code **)(iVar4 + 0x24))(iVar4,DAT_00202fd0 + 0x202470), iVar6 == 0))))
    goto LAB_002022c4;
    pre_authorized_call_hook(iVar2,iVar4);
    iVar7 = json_object_new_object();
    __ptr = (void *)qcgireq_getquery(3);
    iVar6 = json_object_new_object();
    uStack_10044 = 0;
    pcVar3 = getenv((char *)(DAT_00202fd4 + 0x2024bc));
    pcVar9 = getenv((char *)(DAT_00202fd8 + 0x2024d0));
    if (pcVar3 == (char *)0x0) {
LAB_0020266c:
      iVar14 = json_object_object_get_ex(iVar6,DAT_00203014 + 0x202688,&uStack_10044);
      iVar12 = iVar6;
      if (iVar14 == 0) {
        FCGI_printf(DAT_00203068 + 0x2028bc);
        qcgires_setcontenttype(iVar2,DAT_0020306c + 0x2028cc);
        uVar5 = json_object_new_object();
        uVar13 = json_object_new_int(8);
        json_object_object_add(uVar5,DAT_00203070 + 0x2028f0,uVar13);
        uVar13 = json_object_new_string(DAT_00203074 + 0x2028fc);
        json_object_object_add(uVar5,DAT_00203078 + 0x202910,uVar13);
        uVar13 = json_object_to_json_string(uVar5);
        iVar6 = DAT_0020307c + 0x202928;
LAB_00202880:
        FCGI_printf(iVar6,uVar13);
        json_object_put(uVar5);
LAB_0020288c:
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
      }
      else {
        iVar14 = json_object_get_type(uStack_10044);
        if (iVar14 != 3) {
          FCGI_printf(DAT_00203050 + 0x202818);
          qcgires_setcontenttype(iVar2,DAT_00203054 + 0x202828);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_00203058 + 0x20284c,uVar13);
          uVar13 = json_object_new_string(DAT_0020305c + 0x202858);
          json_object_object_add(uVar5,DAT_00203060 + 0x20286c,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00203064 + 0x202884;
          goto LAB_00202880;
        }
        uVar1 = json_object_get_int64(uStack_10044);
        iVar14 = json_object_object_get_ex(iVar6,DAT_00203018 + 0x2026c4,&uStack_10044);
        if (iVar14 == 0) {
          FCGI_printf(DAT_0020301c + 0x2026dc);
          qcgires_setcontenttype(iVar2,DAT_00203020 + 0x2026ec);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_00203024 + 0x202710,uVar13);
          uVar13 = json_object_new_string(DAT_00203028 + 0x20271c);
          json_object_object_add(uVar5,DAT_0020302c + 0x202730,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00203030 + 0x202748;
          goto LAB_00202880;
        }
        iVar14 = json_object_get_type(uStack_10044);
        if (iVar14 != 3) {
          FCGI_printf(DAT_0020309c + 0x2029ec);
          qcgires_setcontenttype(iVar2,DAT_002030a0 + 0x2029fc);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002030a4 + 0x202a20,uVar13);
          uVar13 = json_object_new_string(DAT_002030a8 + 0x202a2c);
          json_object_object_add(uVar5,DAT_002030ac + 0x202a40,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_002030b0 + 0x202a58;
          goto LAB_00202880;
        }
        uVar5 = json_object_get_int64(uStack_10044);
        iVar14 = json_object_object_get_ex(iVar6,DAT_00203080 + 0x20295c,&uStack_10044);
        if (iVar14 == 0) {
          FCGI_printf(DAT_00203084 + 0x202974);
          qcgires_setcontenttype(iVar2,DAT_00203088 + 0x202984);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_0020308c + 0x2029a8,uVar13);
          uVar13 = json_object_new_string(DAT_00203090 + 0x2029b4);
          json_object_object_add(uVar5,DAT_00203094 + 0x2029c8,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00203098 + 0x2029e0;
          goto LAB_00202880;
        }
        iVar14 = json_object_get_type(uStack_10044);
        if (iVar14 != 3) {
          FCGI_printf(DAT_002030d0 + 0x202b1c);
          qcgires_setcontenttype(iVar2,DAT_002030d4 + 0x202b2c);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002030d8 + 0x202b50,uVar13);
          uVar13 = json_object_new_string(DAT_002030dc + 0x202b5c);
          json_object_object_add(uVar5,DAT_002030e0 + 0x202b70,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_002030e4 + 0x202b88;
          goto LAB_00202880;
        }
        uVar13 = json_object_get_int64(uStack_10044);
        iVar14 = json_object_object_get_ex(iVar6,DAT_002030b4 + 0x202a8c,&uStack_10044);
        if (iVar14 == 0) {
          FCGI_printf(DAT_002030b8 + 0x202aa4);
          qcgires_setcontenttype(iVar2,DAT_002030bc + 0x202ab4);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002030c0 + 0x202ad8,uVar13);
          uVar13 = json_object_new_string(DAT_002030c4 + 0x202ae4);
          json_object_object_add(uVar5,DAT_002030c8 + 0x202af8,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_002030cc + 0x202b10;
          goto LAB_00202880;
        }
        iVar14 = json_object_get_type(uStack_10044);
        if (iVar14 != 3) {
          FCGI_printf(DAT_00203104 + 0x202c4c);
          qcgires_setcontenttype(iVar2,DAT_00203108 + 0x202c5c);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_0020310c + 0x202c80,uVar13);
          uVar13 = json_object_new_string(DAT_00203110 + 0x202c8c);
          json_object_object_add(uVar5,DAT_00203114 + 0x202ca0,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00203118 + 0x202cb8;
          goto LAB_00202880;
        }
        uVar15 = json_object_get_int64(uStack_10044);
        iVar14 = json_object_object_get_ex(iVar6,DAT_002030e8 + 0x202bbc,&uStack_10044);
        if (iVar14 == 0) {
          FCGI_printf(DAT_002030ec + 0x202bd4);
          qcgires_setcontenttype(iVar2,DAT_002030f0 + 0x202be4);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_002030f4 + 0x202c08,uVar13);
          uVar13 = json_object_new_string(DAT_002030f8 + 0x202c14);
          json_object_object_add(uVar5,DAT_002030fc + 0x202c28,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00203100 + 0x202c40;
          goto LAB_00202880;
        }
        iVar14 = json_object_get_type(uStack_10044);
        if (iVar14 != 3) {
          FCGI_printf(DAT_00203130 + 0x202da4);
          qcgires_setcontenttype(iVar2,DAT_00203134 + 0x202db4);
          uVar5 = json_object_new_object();
          uVar13 = json_object_new_int(8);
          json_object_object_add(uVar5,DAT_00203138 + 0x202dd8,uVar13);
          uVar13 = json_object_new_string(DAT_0020313c + 0x202de4);
          json_object_object_add(uVar5,DAT_00203140 + 0x202df8,uVar13);
          uVar13 = json_object_to_json_string(uVar5);
          iVar6 = DAT_00203144 + 0x202e10;
          goto LAB_00202880;
        }
        uVar16 = json_object_get_int64(uStack_10044);
        CMD_Start_Firmware_Update(auStack_10040,uVar13,uVar1,uVar16,uVar5,uVar15,1);
        uVar15 = json_object_new_int(uVar1);
        json_object_object_add(iVar7,DAT_0020311c + 0x202d2c,uVar15);
        uVar5 = json_object_new_int(uVar5);
        json_object_object_add(iVar7,DAT_00203120 + 0x202d48,uVar5);
        uVar5 = json_object_new_int(uVar13);
        json_object_object_add(iVar7,DAT_00203124 + 0x202d64,uVar5);
        if (iStack_1003c == 0) {
          qcgires_setcontenttype(iVar2,DAT_00203128 + 0x202d7c);
          uVar5 = json_object_to_json_string(iVar7);
          FCGI_printf(DAT_0020312c + 0x202d94,uVar5);
          goto LAB_0020288c;
        }
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        if (__ptr != (void *)0x0) {
          free(__ptr);
        }
        if (pcVar3 != (char *)0x0) {
          iVar7 = strcasecmp(pcVar3,(char *)(DAT_00203148 + 0x202e48));
          if ((iVar7 == 0 || pcVar9 == (char *)0x0) ||
             ((iVar7 = strcasecmp(pcVar3,(char *)(DAT_0020314c + 0x202e6c)), iVar7 == 0 &&
              (iVar7 = strncasecmp(pcVar9,(char *)(DAT_00203150 + 0x202e88),0x10), iVar7 == 0)))) {
            if (iVar6 != 0) {
              json_object_put(iVar6);
              iVar12 = 0;
            }
          }
          else if (iVar6 != 0) {
            iVar12 = 0;
            json_object_put(iVar6);
          }
        }
        iVar6 = json_object_new_object();
        uVar5 = json_object_new_string_len(DAT_00203154 + 0x202ed4,0x1f);
        json_object_object_add(iVar6,DAT_00203158 + 0x202ee8,uVar5);
        uVar5 = json_object_new_int(0x5a2);
        json_object_object_add(iVar6,DAT_0020315c + 0x202f04,uVar5);
        FCGI_printf(DAT_00203164 + 0x202f18,DAT_00203160 + 0x202f14);
        qcgires_setcontenttype(iVar2,DAT_00203168 + 0x202f28);
        uVar5 = json_object_to_json_string(iVar6);
        FCGI_printf(DAT_0020316c + 0x202f40,uVar5);
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
      }
      iVar6 = iVar12;
      if (pcVar3 != (char *)0x0) {
LAB_002027f8:
        if (iVar6 != 0) {
          json_object_put(iVar6);
        }
      }
    }
    else {
      iVar12 = strcasecmp(pcVar3,(char *)(DAT_00202fdc + 0x2024ec));
      if (__ptr == (void *)0x0 || iVar12 == 0) {
        iVar12 = strcasecmp(pcVar3,(char *)(DAT_00203034 + 0x202758));
        if (__ptr != (void *)0x0 || iVar12 != 0) goto LAB_0020266c;
        json_object_put(iVar6);
        FCGI_printf(DAT_00203038 + 0x202774);
        qcgires_setcontenttype(iVar2,DAT_0020303c + 0x202784);
        uVar5 = json_object_new_object();
        uVar13 = json_object_new_int(8);
        json_object_object_add(uVar5,DAT_00203040 + 0x2027a8,uVar13);
        uVar13 = json_object_new_string(DAT_00203044 + 0x2027b4);
        json_object_object_add(uVar5,DAT_00203048 + 0x2027c8,uVar13);
        uVar13 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_0020304c + 0x2027e0,uVar13);
        json_object_put(uVar5);
        if (iVar7 != 0) {
          json_object_put(iVar7);
        }
        goto LAB_002027f8;
      }
      if (pcVar9 == (char *)0x0) goto LAB_0020266c;
      iVar12 = strcasecmp(pcVar3,(char *)(DAT_00202fe0 + 0x202510));
      if (iVar12 != 0) {
LAB_00202658:
        json_object_put(iVar6);
        iVar6 = json_tokener_parse(__ptr);
        goto LAB_0020266c;
      }
      pcVar11 = (char *)(DAT_00202fe4 + 0x20252c);
      iVar12 = strncasecmp(pcVar9,pcVar11,0x10);
      if (iVar12 != 0) goto LAB_00202658;
      json_object_put(iVar6);
      iVar6 = json_tokener_parse(__ptr);
      if (iVar6 != 0) goto LAB_0020266c;
      FCGI_printf(DAT_00202fe8 + 0x20255c);
      qcgires_setcontenttype(iVar2,pcVar11);
      uVar5 = json_object_new_object();
      uVar13 = json_object_new_int(8);
      json_object_object_add(uVar5,DAT_00202fec + 0x20258c,uVar13);
      uVar13 = json_object_new_string(DAT_00202ff0 + 0x202598);
      json_object_object_add(uVar5,DAT_00202ff4 + 0x2025ac,uVar13);
      uVar13 = json_object_to_json_string(uVar5);
      FCGI_printf(DAT_00202ff8 + 0x2025c4,uVar13);
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
LAB_0020223c:
  post_call_hook(iVar2);
  if (iVar2 != 0) {
    (**(code **)(iVar2 + 0x58))(iVar2);
  }
  uVar5 = FCGI_fflush(*(int *)(iVar18 + DAT_00202f98) + 8);
  uVar17 = uVar17 ^ **(uint **)(DAT_00202f9c + 0x202280 + DAT_00202f74);
  if (uVar17 == 0) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar5,uVar17,0);
}

