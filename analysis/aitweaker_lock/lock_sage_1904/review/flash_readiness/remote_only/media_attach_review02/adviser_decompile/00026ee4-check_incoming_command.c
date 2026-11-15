
undefined4 check_incoming_command(void)

{
  size_t __size;
  int *piVar1;
  int iVar2;
  uint *__ptr;
  code *pcVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  ushort local_80;
  undefined2 uStack_7e;
  undefined2 local_7c;
  ushort uStack_7a;
  undefined1 auStack_78 [52];
  undefined1 auStack_44 [52];
  
  piVar1 = DAT_00027374;
  if (0 < *DAT_00027374) {
    local_80 = 0;
    uStack_7e = 0;
    local_7c = 0;
    uStack_7a = 0;
    iVar2 = sigwrap_read(*DAT_00027374,&local_80,8);
    uVar5 = DAT_000273bc;
    if (0 < iVar2) {
      if (local_80 == 8) {
        sm_set_stop_signal(uStack_7a);
        return 0;
      }
      if (local_80 < 9) {
        if (local_80 == 3) {
          if (*(int *)(DAT_00027398 + 0x308) != 1) {
            return 0;
          }
          if (*(char *)(DAT_00027388 + 0x14) == '\0') {
            return 0;
          }
          *DAT_0002739c = 3;
          return 0;
        }
        if (local_80 < 4) {
          if (local_80 == 0) {
            if (*(int *)(DAT_00027398 + 0x308) == 1) {
              *DAT_000273a0 = 1;
            }
            sm_wake_up_record_thread();
            return 0;
          }
          if (local_80 == 2) {
            iVar2 = dlopen(DAT_0002738c,1);
            if (iVar2 == 0) {
              uVar5 = dlerror();
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000273b8,DAT_0002737c,DAT_000273b4,uVar5);
              return 0;
            }
            pcVar3 = (code *)dlsym(iVar2,DAT_00027390);
            if (pcVar3 != (code *)0x0) {
              *DAT_00027394 = 1;
              iVar4 = (*pcVar3)(local_80);
              if (iVar4 < 0) {
                IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000273d4,DAT_0002737c,DAT_000273d0);
              }
            }
            goto LAB_0002701c;
          }
        }
        else {
          if (local_80 == 5) {
            if (*(int *)(DAT_00027398 + 0x308) != 1) {
              return 0;
            }
            if (*(char *)(DAT_00027388 + 0x14) == '\x01') {
              IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000273d8,DAT_0002737c,0x141);
              return 0;
            }
            *(undefined1 *)(DAT_00027388 + 0x14) = 1;
            iVar2 = dlopen(uVar5,1);
            if (iVar2 == 0) {
              uVar5 = dlerror();
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000273b8,DAT_0002737c,DAT_000273e4,uVar5);
              return 0;
            }
            pcVar3 = (code *)dlsym(iVar2,DAT_000273c0);
            if ((pcVar3 != (code *)0x0) && (iVar4 = (*pcVar3)(), iVar4 < 0)) {
              IDBG_LINUXAPP_DbgOut(0x80,DAT_000273c4,DAT_0002737c,0x154);
              dlclose(iVar2);
              return 0;
            }
LAB_0002701c:
            dlclose(iVar2);
            return 0;
          }
          if (local_80 < 5) {
            if (*(int *)(DAT_00027398 + 0x308) != 1) {
              return 0;
            }
            if (*(char *)(DAT_00027388 + 0x14) == '\0') {
              return 0;
            }
            *DAT_0002739c = 4;
            return 0;
          }
          if (local_80 == 6) {
            *(undefined1 *)(DAT_00027388 + 0x14) = 0;
            return 0;
          }
        }
      }
      else {
        if (local_80 == 0xe0) {
          handleconfupdate();
          return 0;
        }
        if (local_80 < 0xe1) {
          if (local_80 == 0x36) {
            __size = CONCAT22(local_7c,uStack_7e);
            if (__size == 0) {
              return 0;
            }
            __ptr = malloc(__size);
            if (__ptr == (uint *)0x0) {
              return 0;
            }
            iVar2 = sigwrap_read(*piVar1,__ptr,__size);
            if (iVar2 == -1) {
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000273ec,DAT_0002737c,DAT_000273e8);
            }
            Ondisconnect_session((uint)(byte)__ptr[1] << 0x18 | *__ptr >> 8,(char)*__ptr);
            free(__ptr);
            return 0;
          }
          if (local_80 == 0x38) {
            if (*(int *)(DAT_00027398 + 0x1e4) == 0) {
              return 0;
            }
            if (*(int *)(DAT_00027398 + 0x1ec) != 1) {
              return 0;
            }
            iVar2 = sm_get_kvm_num_session();
            if (iVar2 < 1) {
              return 0;
            }
            sm_set_vmedia_update_status();
            return 0;
          }
          if (local_80 == 0x22) {
            if (uStack_7a == 0) {
              ResetKbdLEDStatus();
            }
            sm_set_power_status(uStack_7a);
            sm_set_power_status_send_all();
            return 0;
          }
        }
        else {
          if (local_80 == 0xe2) {
            sm_set_stop_signal(2);
            return 1;
          }
          if (local_80 < 0xe2) {
            if ((*(int *)(DAT_00027398 + 0x2b0) == 1) &&
               (iVar2 = getLicenseStatus(DAT_000273c8), *DAT_000273cc != iVar2)) {
              *DAT_000273cc = iVar2;
              sm_set_media_license_send();
            }
            iVar2 = sm_get_services_info(auStack_44,auStack_78,*DAT_000273a4);
            if (iVar2 == 0) {
              return 0;
            }
            IDBG_LINUXAPP_DbgOut(0x86,DAT_000273a8);
            return 0;
          }
          if (local_80 == 0xe8) {
            iVar2 = IsFeatureEnabled(DAT_00027378);
            if (iVar2 == 0) {
              return 0;
            }
            iVar2 = IsFeatureEnabled(DAT_000273ac);
            if (iVar2 == 0) {
              return 0;
            }
            uVar6 = (uint)uStack_7a;
            if (1 < uVar6 - 1) {
              IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000273e0,DAT_0002737c,DAT_000273dc);
              return 0;
            }
            *DAT_000273b0 = uVar6;
            if (uVar6 != 2) {
              return 0;
            }
            iVar2 = sm_get_num_session();
            if (iVar2 < 1) {
              return 0;
            }
            sm_set_stop_signal(0xe);
            return 0;
          }
        }
      }
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00027384,DAT_0002737c,DAT_00027380,local_80);
    }
  }
  return 0;
}

