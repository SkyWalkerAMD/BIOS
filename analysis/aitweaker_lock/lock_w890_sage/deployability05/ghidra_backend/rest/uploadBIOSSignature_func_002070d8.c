
void uploadBIOSSignature_func(undefined4 param_1,undefined4 param_2)

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
  
  iVar5 = DAT_00207754;
  pcVar1 = getenv((char *)(DAT_00207750 + 0x2070ec));
  iVar2 = qcgireq_setoption(0,1,DAT_00207758 + 0x207100,0,param_1,param_2);
  if (pcVar1 == (char *)0x0) {
LAB_00207118:
    FCGI_printf(DAT_0020775c + 0x207124);
    qcgires_setcontenttype(iVar2,DAT_00207760 + 0x207134);
    uVar3 = json_object_new_object();
    uVar4 = json_object_new_int(5);
    json_object_object_add(uVar3,DAT_00207764 + 0x207158,uVar4);
    uVar4 = json_object_new_string(DAT_00207768 + 0x207164);
    json_object_object_add(uVar3,DAT_0020776c + 0x207178,uVar4);
    uVar4 = json_object_to_json_string(uVar3);
    iVar5 = DAT_00207770 + 0x207190;
  }
  else {
    uVar12 = strtoull(pcVar1,(char **)0x0,10);
    if (uVar12 == 0) goto LAB_00207118;
    if ((uint)-(int)(uVar12 >> 0x20) < (uint)((uint)uVar12 < 0x4300001)) {
      if (iVar2 == 0) {
        FCGI_printf(DAT_0020778c + 0x20726c);
        qcgires_setcontenttype(0,DAT_00207790 + 0x20727c);
        uVar3 = json_object_new_object();
        uVar4 = json_object_new_int(7);
        json_object_object_add(uVar3,DAT_00207794 + 0x2072a0,uVar4);
        uVar4 = json_object_new_string(DAT_00207798 + 0x2072ac);
        json_object_object_add(uVar3,DAT_0020779c + 0x2072c0,uVar4);
        uVar4 = json_object_to_json_string(uVar3);
        iVar5 = DAT_002077a0 + 0x2072d8;
      }
      else {
        iVar2 = qcgireq_parse(iVar2,0);
        if (iVar2 == 0) {
          FCGI_printf(DAT_002077a4 + 0x2072f8);
          qcgires_setcontenttype(0,DAT_002077a8 + 0x207308);
          uVar3 = json_object_new_object();
          uVar4 = json_object_new_int(7);
          json_object_object_add(uVar3,DAT_002077ac + 0x20732c,uVar4);
          uVar4 = json_object_new_string(DAT_002077b0 + 0x207338);
          json_object_object_add(uVar3,DAT_002077b4 + 0x20734c,uVar4);
          uVar4 = json_object_to_json_string(uVar3);
          iVar5 = DAT_002077b8 + 0x207364;
        }
        else {
          pre_call_hook();
          iVar6 = qcgisess_init(iVar2,0);
          if (iVar6 != 0) {
            pcVar1 = getenv((char *)(DAT_002077d8 + 0x20740c));
            iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_002077dc + 0x207420);
            uVar11 = (uint)(iVar7 != 1);
            if (pcVar1 == (char *)0x0) {
              uVar11 = 1;
            }
            if (uVar11 == 0) {
              sVar8 = strlen(pcVar1);
              iVar7 = DAT_00207800 + 0x207530;
              pcVar9 = (char *)(**(code **)(iVar6 + 0x18))(iVar6);
              sVar10 = strlen(pcVar9);
              if (sVar8 != sVar10) goto LAB_0020743c;
              pcVar9 = (char *)(**(code **)(iVar6 + 0x18))(iVar6,iVar7,uVar11);
              __s = (char *)(**(code **)(iVar6 + 0x18))(iVar6,iVar7,uVar11);
              sVar8 = strlen(__s);
              iVar7 = strncmp(pcVar9,pcVar1,sVar8);
              if (((iVar7 != 0) ||
                  (iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207804 + 0x20759c), iVar7 != 0))
                 || ((iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207808 + 0x2075b8), iVar7 == 1
                     && (iVar7 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_0020780c + 0x2075d4),
                        iVar7 == 0)))) goto LAB_0020743c;
              pre_authorized_call_hook(iVar2,iVar6);
              uVar3 = json_object_new_object();
              pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_00207810 + 0x207600,0);
              iVar7 = rename(pcVar1,(char *)(DAT_00207814 + 0x207614));
              if (iVar7 == -1) {
                FCGI_fprintf(*(int *)(iVar5 + 0x20710c + DAT_00207818) + 0x10,
                             DAT_00207820 + 0x20763c,DAT_0020781c + 0x207634);
              }
              qcgires_setcontenttype(iVar2,DAT_00207824 + 0x207650);
              if (iVar7 == 0) {
                uVar4 = json_object_new_int(0);
                json_object_object_add(uVar3,DAT_00207828 + 0x207674,uVar4);
                uVar4 = json_object_to_json_string(uVar3);
                iVar5 = DAT_0020782c + 0x20768c;
              }
              else {
                FCGI_printf(DAT_00207848 + 0x207714);
                uVar4 = json_object_new_int(iVar7);
                json_object_object_add(uVar3,DAT_0020784c + 0x207730,uVar4);
                uVar4 = json_object_to_json_string(uVar3);
                iVar5 = DAT_00207850 + 0x207748;
              }
              FCGI_printf(iVar5,uVar4);
              json_object_put(uVar3);
            }
            else {
LAB_0020743c:
              FCGI_printf(DAT_002077e0 + 0x207448);
              FCGI_printf(DAT_002077e4 + 0x207454);
              qcgires_setcontenttype(iVar2,DAT_002077e8 + 0x207464);
              uVar3 = json_object_new_object();
              uVar4 = json_object_new_int(7);
              json_object_object_add(uVar3,DAT_002077ec + 0x207488,uVar4);
              iVar5 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_002077f0 + 0x20749c);
              if (iVar5 == 1) {
                uVar4 = json_object_new_string(DAT_002077f4 + 0x2074b0);
                iVar5 = DAT_002077f8 + 0x2074c0;
              }
              else {
                iVar5 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207830 + 0x2076ac);
                if ((iVar5 == 1) &&
                   (iVar5 = (**(code **)(iVar6 + 0x24))(iVar6,DAT_00207834 + 0x2076c8), iVar5 == 0))
                {
                  uVar4 = json_object_new_string(DAT_00207838 + 0x2076dc);
                  iVar5 = DAT_0020783c + 0x2076ec;
                }
                else {
                  uVar4 = json_object_new_string(DAT_00207840 + 0x2076f8);
                  iVar5 = DAT_00207844 + 0x207708;
                }
              }
              json_object_object_add(uVar3,iVar5,uVar4);
              uVar4 = json_object_to_json_string(uVar3);
              FCGI_printf(DAT_002077fc + 0x2074dc,uVar4);
              json_object_put(uVar3);
              qcgisess_clear(iVar6);
            }
            post_authorized_call_hook(iVar2,iVar6);
            qcgisess_save(iVar6);
            (**(code **)(iVar6 + 0x58))(iVar6);
            goto LAB_00207198;
          }
          FCGI_printf(DAT_002077bc + 0x207388);
          FCGI_printf(DAT_002077c0 + 0x207394);
          qcgires_setcontenttype(iVar2,DAT_002077c4 + 0x2073a4);
          uVar3 = json_object_new_object();
          uVar4 = json_object_new_int(7);
          json_object_object_add(uVar3,DAT_002077c8 + 0x2073c8,uVar4);
          uVar4 = json_object_new_string(DAT_002077cc + 0x2073d4);
          json_object_object_add(uVar3,DAT_002077d0 + 0x2073e8,uVar4);
          uVar4 = json_object_to_json_string(uVar3);
          iVar5 = DAT_002077d4 + 0x207400;
        }
      }
    }
    else {
      FCGI_printf(DAT_00207774 + 0x2071ec);
      qcgires_setcontenttype(iVar2,DAT_00207778 + 0x2071fc);
      uVar3 = json_object_new_object();
      uVar4 = json_object_new_int(6);
      json_object_object_add(uVar3,DAT_0020777c + 0x207220,uVar4);
      uVar4 = json_object_new_string(DAT_00207780 + 0x20722c);
      json_object_object_add(uVar3,DAT_00207784 + 0x207240,uVar4);
      uVar4 = json_object_to_json_string(uVar3);
      iVar5 = DAT_00207788 + 0x207258;
    }
  }
  FCGI_printf(iVar5,uVar4);
  json_object_put(uVar3);
LAB_00207198:
  post_call_hook(iVar2);
  if (iVar2 != 0) {
                    /* WARNING: Could not recover jumptable at 0x002071b8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(iVar2 + 0x58))(iVar2);
    return;
  }
  return;
}

