
void uploadBIOSFWImage_func(undefined4 param_1,undefined4 param_2)

{
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  size_t sVar8;
  char *pcVar9;
  size_t sVar10;
  char *__s;
  uint uVar11;
  ulonglong uVar12;
  
  iVar5 = DAT_00206fd8;
  pcVar1 = getenv((char *)(DAT_00206fd4 + 0x206970));
  iVar2 = qcgireq_setoption(0,1,DAT_00206fdc + 0x206984,0,param_1,param_2);
  if (pcVar1 == (char *)0x0) {
LAB_0020699c:
    FCGI_printf(DAT_00206fe0 + 0x2069a8);
    qcgires_setcontenttype(iVar2,DAT_00206fe4 + 0x2069b8);
    uVar3 = json_object_new_object();
    uVar4 = json_object_new_int(5);
    json_object_object_add(uVar3,DAT_00206fe8 + 0x2069dc,uVar4);
    uVar4 = json_object_new_string(DAT_00206fec + 0x2069e8);
    json_object_object_add(uVar3,DAT_00206ff0 + 0x2069fc,uVar4);
    uVar4 = json_object_to_json_string(uVar3);
    iVar5 = DAT_00206ff4 + 0x206a14;
  }
  else {
    uVar12 = strtoull(pcVar1,(char **)0x0,10);
    if (uVar12 == 0) goto LAB_0020699c;
    if ((uint)-(int)(uVar12 >> 0x20) < (uint)((uint)uVar12 < 0x4300001)) {
      if (iVar2 == 0) {
        FCGI_printf(DAT_00207010 + 0x206af0);
        qcgires_setcontenttype(0,DAT_00207014 + 0x206b00);
        uVar3 = json_object_new_object();
        uVar4 = json_object_new_int(7);
        json_object_object_add(uVar3,DAT_00207018 + 0x206b24,uVar4);
        uVar4 = json_object_new_string(DAT_0020701c + 0x206b30);
        json_object_object_add(uVar3,DAT_00207020 + 0x206b44,uVar4);
        uVar4 = json_object_to_json_string(uVar3);
        iVar5 = DAT_00207024 + 0x206b5c;
      }
      else {
        iVar2 = qcgireq_parse(iVar2,0);
        if (iVar2 == 0) {
          FCGI_printf(DAT_00207028 + 0x206b7c);
          qcgires_setcontenttype(0,DAT_0020702c + 0x206b8c);
          uVar3 = json_object_new_object();
          uVar4 = json_object_new_int(7);
          json_object_object_add(uVar3,DAT_00207030 + 0x206bb0,uVar4);
          uVar4 = json_object_new_string(DAT_00207034 + 0x206bbc);
          json_object_object_add(uVar3,DAT_00207038 + 0x206bd0,uVar4);
          uVar4 = json_object_to_json_string(uVar3);
          iVar5 = DAT_0020703c + 0x206be8;
        }
        else {
          pre_call_hook();
          iVar6 = qcgisess_init(iVar2,0);
          if (iVar6 != 0) {
            pcVar1 = getenv((char *)(DAT_0020705c + 0x206c90));
            iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207060 + 0x206ca4);
            uVar11 = (uint)(iVar7 != 1);
            if (pcVar1 == (char *)0x0) {
              uVar11 = 1;
            }
            if (uVar11 == 0) {
              sVar8 = strlen(pcVar1);
              iVar7 = DAT_00207084 + 0x206db4;
              pcVar9 = (char *)(**(code **)(iVar6 + 0x18))(iVar6);
              sVar10 = strlen(pcVar9);
              if (sVar8 != sVar10) goto LAB_00206cc0;
              pcVar9 = (char *)(**(code **)(iVar6 + 0x18))(iVar6,iVar7,uVar11);
              __s = (char *)(**(code **)(iVar6 + 0x18))(iVar6,iVar7,uVar11);
              sVar8 = strlen(__s);
              iVar7 = strncmp(pcVar9,pcVar1,sVar8);
              if (((iVar7 != 0) ||
                  (iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207088 + 0x206e20), iVar7 != 0))
                 || ((iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_0020708c + 0x206e3c), iVar7 == 1
                     && (iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207090 + 0x206e58),
                        iVar7 == 0)))) goto LAB_00206cc0;
              pre_authorized_call_hook(iVar2,iVar6);
              uVar3 = json_object_new_object();
              pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_00207094 + 0x206e84,0);
              iVar7 = rename(pcVar1,(char *)(DAT_00207098 + 0x206e98));
              if (iVar7 == -1) {
                FCGI_fprintf(*(int *)(iVar5 + 0x206990 + DAT_0020709c) + 0x10,
                             DAT_002070a4 + 0x206ec0,DAT_002070a0 + 0x206eb8);
              }
              qcgires_setcontenttype(iVar2,DAT_002070a8 + 0x206ed4);
              if (iVar7 == 0) {
                uVar4 = json_object_new_int(0);
                json_object_object_add(uVar3,DAT_002070ac + 0x206ef8,uVar4);
                uVar4 = json_object_to_json_string(uVar3);
                iVar5 = DAT_002070b0 + 0x206f10;
              }
              else {
                FCGI_printf(DAT_002070cc + 0x206f98);
                uVar4 = json_object_new_int(iVar7);
                json_object_object_add(uVar3,DAT_002070d0 + 0x206fb4,uVar4);
                uVar4 = json_object_to_json_string(uVar3);
                iVar5 = DAT_002070d4 + 0x206fcc;
              }
              FCGI_printf(iVar5,uVar4);
              json_object_put(uVar3);
            }
            else {
LAB_00206cc0:
              FCGI_printf(DAT_00207064 + 0x206ccc);
              FCGI_printf(DAT_00207068 + 0x206cd8);
              qcgires_setcontenttype(iVar2,DAT_0020706c + 0x206ce8);
              uVar3 = json_object_new_object();
              uVar4 = json_object_new_int(7);
              json_object_object_add(uVar3,DAT_00207070 + 0x206d0c,uVar4);
              iVar5 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207074 + 0x206d20);
              if (iVar5 == 1) {
                uVar4 = json_object_new_string(DAT_00207078 + 0x206d34);
                iVar5 = DAT_0020707c + 0x206d44;
              }
              else {
                iVar5 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_002070b4 + 0x206f30);
                if ((iVar5 == 1) &&
                   (iVar5 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_002070b8 + 0x206f4c), iVar5 == 0))
                {
                  uVar4 = json_object_new_string(DAT_002070bc + 0x206f60);
                  iVar5 = DAT_002070c0 + 0x206f70;
                }
                else {
                  uVar4 = json_object_new_string(DAT_002070c4 + 0x206f7c);
                  iVar5 = DAT_002070c8 + 0x206f8c;
                }
              }
              json_object_object_add(uVar3,iVar5,uVar4);
              uVar4 = json_object_to_json_string(uVar3);
              FCGI_printf(DAT_00207080 + 0x206d60,uVar4);
              json_object_put(uVar3);
              qcgisess_clear(iVar6);
            }
            post_authorized_call_hook(iVar2,iVar6);
            qcgisess_save(iVar6);
            (**(code **)(iVar6 + 0x58))(iVar6);
            goto LAB_00206a1c;
          }
          FCGI_printf(DAT_00207040 + 0x206c0c);
          FCGI_printf(DAT_00207044 + 0x206c18);
          qcgires_setcontenttype(iVar2,DAT_00207048 + 0x206c28);
          uVar3 = json_object_new_object();
          uVar4 = json_object_new_int(7);
          json_object_object_add(uVar3,DAT_0020704c + 0x206c4c,uVar4);
          uVar4 = json_object_new_string(DAT_00207050 + 0x206c58);
          json_object_object_add(uVar3,DAT_00207054 + 0x206c6c,uVar4);
          uVar4 = json_object_to_json_string(uVar3);
          iVar5 = DAT_00207058 + 0x206c84;
        }
      }
    }
    else {
      FCGI_printf(DAT_00206ff8 + 0x206a70);
      qcgires_setcontenttype(iVar2,DAT_00206ffc + 0x206a80);
      uVar3 = json_object_new_object();
      uVar4 = json_object_new_int(6);
      json_object_object_add(uVar3,DAT_00207000 + 0x206aa4,uVar4);
      uVar4 = json_object_new_string(DAT_00207004 + 0x206ab0);
      json_object_object_add(uVar3,DAT_00207008 + 0x206ac4,uVar4);
      uVar4 = json_object_to_json_string(uVar3);
      iVar5 = DAT_0020700c + 0x206adc;
    }
  }
  FCGI_printf(iVar5,uVar4);
  json_object_put(uVar3);
LAB_00206a1c:
  post_call_hook(iVar2);
  if (iVar2 != 0) {
                    /* WARNING: Could not recover jumptable at 0x00206a3c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(iVar2 + 0x58))(iVar2);
    return;
  }
  return;
}

