
void uploadBIOSSignature_func(void)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char *__s1;
  char *__s;
  size_t __n;
  undefined4 uVar5;
  undefined4 uVar6;
  ulonglong uVar7;
  
  pcVar1 = getenv(DAT_001367cc);
  iVar2 = qcgireq_setoption(0,1,DAT_001367d0);
  if (pcVar1 != (char *)0x0) {
    uVar7 = strtoull(pcVar1,(char **)0x0,10);
    if (uVar7 != 0) {
      if (((int)(uVar7 >> 0x20) != 0 || 0x42fffff < (uint)uVar7) && uVar7 != 0x4300000) {
        FCGI_printf(DAT_00136810);
        qcgires_setcontenttype(iVar2,DAT_001367ec);
        uVar6 = json_object_new_object();
        uVar5 = 6;
        goto LAB_00136618;
      }
      if (iVar2 == 0) {
        qcgires_error(0,DAT_00136824);
      }
      iVar2 = qcgireq_parse(iVar2,0);
      if (iVar2 == 0) {
        FCGI_printf(DAT_00136818);
        qcgires_setcontenttype(0,DAT_001367ec);
        uVar5 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar5,DAT_0013681c,uVar6);
        uVar6 = json_object_new_string(DAT_00136820);
        json_object_object_add(uVar5,DAT_00136804,uVar6);
        uVar6 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_001367f4,uVar6);
        json_object_put(uVar5);
        post_call_hook(0);
        return;
      }
      pre_call_hook();
      iVar3 = qcgisess_init(iVar2,0);
      if (iVar3 == 0) {
        FCGI_printf(DAT_001367f8);
        FCGI_printf(DAT_001367fc);
        qcgires_setcontenttype(iVar2,DAT_001367ec);
        uVar5 = json_object_new_object();
        uVar6 = json_object_new_int(7);
        json_object_object_add(uVar5,DAT_001367f0,uVar6);
        uVar6 = json_object_new_string(DAT_00136800);
        json_object_object_add(uVar5,DAT_00136804,uVar6);
        uVar6 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_001367f4,uVar6);
        json_object_put(uVar5);
        goto LAB_001365e0;
      }
      pcVar1 = getenv(DAT_001367d4);
      iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_001367d8);
      if (iVar4 == 1 && pcVar1 != (char *)0x0) {
        __s1 = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_001367dc,0);
        __s = (char *)(**(code **)(iVar3 + 0x18))(iVar3,DAT_001367dc,0);
        __n = strlen(__s);
        iVar4 = strncmp(__s1,pcVar1,__n);
        if ((iVar4 != 0) || (iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_001367e0), iVar4 != 0))
        goto LAB_00136530;
        pre_authorized_call_hook(iVar2,iVar3);
        uVar5 = json_object_new_object();
        pcVar1 = (char *)(**(code **)(iVar2 + 0x18))(iVar2,DAT_001367e4,0);
        iVar4 = rename(pcVar1,DAT_001367e8);
        if (iVar4 == -1) {
          FCGI_fprintf(DAT_00136830,DAT_00136828,DAT_0013682c);
          qcgires_setcontenttype(iVar2,DAT_001367ec);
LAB_001367c0:
          FCGI_printf(DAT_00136834);
        }
        else {
          qcgires_setcontenttype(iVar2,DAT_001367ec);
          if (iVar4 != 0) goto LAB_001367c0;
        }
        uVar6 = json_object_new_int(iVar4);
        json_object_object_add(uVar5,DAT_001367f0,uVar6);
        uVar6 = json_object_to_json_string(uVar5);
        FCGI_printf(DAT_001367f4,uVar6);
        json_object_put(uVar5);
      }
      else {
LAB_00136530:
        FCGI_printf(DAT_001367f8);
        FCGI_printf(DAT_001367fc);
        qcgires_setcontenttype(iVar2,DAT_001367ec);
        uVar6 = json_object_new_object();
        uVar5 = json_object_new_int(7);
        json_object_object_add(uVar6,DAT_001367f0,uVar5);
        iVar4 = (**(code **)(iVar3 + 0x24))(iVar3,DAT_001367e0);
        uVar5 = DAT_00136800;
        if (iVar4 == 1) {
          uVar5 = DAT_00136814;
        }
        uVar5 = json_object_new_string(uVar5);
        json_object_object_add(uVar6,DAT_00136804,uVar5);
        uVar5 = json_object_to_json_string(uVar6);
        FCGI_printf(DAT_001367f4,uVar5);
        json_object_put(uVar6);
        qcgisess_clear(iVar3);
      }
      post_authorized_call_hook(iVar2,iVar3);
      qcgisess_save(iVar3);
      (**(code **)(iVar3 + 0x58))(iVar3);
LAB_001365e0:
      post_call_hook(iVar2);
                    /* WARNING: Could not recover jumptable at 0x001365f4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(iVar2 + 0x58))(iVar2);
      return;
    }
  }
  FCGI_printf(DAT_00136808);
  qcgires_setcontenttype(iVar2,DAT_001367ec);
  uVar6 = json_object_new_object();
  uVar5 = 5;
LAB_00136618:
  uVar5 = json_object_new_int(uVar5);
  json_object_object_add(uVar6,DAT_001367f0,uVar5);
  uVar5 = json_object_new_string(DAT_0013680c);
  json_object_object_add(uVar6,DAT_00136804,uVar5);
  uVar5 = json_object_to_json_string(uVar6);
  FCGI_printf(DAT_001367f4,uVar5);
  json_object_put(uVar6);
  post_call_hook(iVar2);
  if (iVar2 != 0) {
                    /* WARNING: Could not recover jumptable at 0x0013667c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(iVar2 + 0x58))(iVar2);
    return;
  }
  return;
}

