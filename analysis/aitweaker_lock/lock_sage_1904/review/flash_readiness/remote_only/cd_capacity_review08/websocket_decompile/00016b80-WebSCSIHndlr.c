
void WebSCSIHndlr(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  pthread_t __th;
  undefined4 uVar6;
  int iVar7;
  bool bVar8;
  undefined1 auStack_68 [41];
  undefined1 local_3f;
  undefined1 local_3d;
  undefined1 local_3c;
  undefined1 local_3b;
  undefined1 local_3a;
  undefined1 local_39;
  undefined1 local_38;
  undefined1 local_37;
  undefined1 local_36;
  
  iVar7 = **(int **)(DAT_00016dbc + 0x16b94 + DAT_00016dc0);
  iVar3 = cdrom_start(*(undefined4 *)
                       (*(int *)(DAT_00016dbc + 0x16b94 + DAT_00016dc4) + *(int *)(iVar7 + 0x48) * 4
                       ));
  *(int *)(DAT_00016dc8 + 0x16c28) = iVar3;
  if (iVar3 != -1) {
    do {
      if (*(int *)(iVar7 + 0x34) == 1) {
        iVar5 = nbd_read_req(iVar7 + 0x34);
        iVar3 = DAT_00016dcc;
        if (iVar5 == -1) goto code_r0x00016d80;
        memset(auStack_68,0,0x3e);
        local_3f = 0xa8;
        uVar1 = *(uint *)(iVar7 + 0x4c);
        uVar4 = *(uint *)(iVar7 + 0x68);
        uVar2 = *(uint *)(iVar7 + 0x50);
        bVar8 = uVar2 <= uVar4;
        if (uVar4 == uVar2) {
          bVar8 = uVar1 <= *(uint *)(iVar7 + 100);
        }
        if (bVar8) {
          uVar4 = FUN_0001fd78(*(uint *)(iVar7 + 100),uVar4,uVar1,uVar2);
          uVar4 = (uVar4 ^ (uVar4 >> 0x10 | uVar4 << 0x10)) >> 8 & 0xffff00ff ^
                  (uVar4 >> 8 | uVar4 << 0x18);
        }
        else {
          uVar4 = 0;
        }
        local_3c = (undefined1)(uVar4 >> 8);
        local_3d = (undefined1)uVar4;
        local_3b = (undefined1)(uVar4 >> 0x10);
        local_3a = (undefined1)(uVar4 >> 0x18);
        if (uVar2 == 0 && uVar1 <= *(uint *)(iVar7 + 0x74)) {
          uVar6 = FUN_0001fd78(*(uint *)(iVar7 + 0x74),0,uVar1,uVar2);
        }
        else {
          uVar6 = 1;
        }
        local_39 = (undefined1)uVar6;
        local_36 = (undefined1)((uint)uVar6 >> 0x18);
        local_38 = (undefined1)((uint)uVar6 >> 8);
        local_37 = (undefined1)((uint)uVar6 >> 0x10);
        FUN_00015bc8(auStack_68);
        *(undefined1 *)(iVar7 + 0x35) = 0;
        *(undefined1 *)(iVar7 + 0x36) = 0;
        *(undefined1 *)(iVar7 + 0x37) = 0;
        *(undefined1 *)(iVar7 + 0x34) = 2;
      }
      NanoSleep(1);
    } while( true );
  }
LAB_00016d98:
  nbd_disconnect(iVar7 + 0x34);
  __th = pthread_self();
  pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
code_r0x00016d80:
  if (*(int *)(DAT_00016dcc + 0x16de0) != -1) {
    cdrom_stop();
    *(undefined4 *)(iVar3 + 0x16de0) = 0xffffffff;
  }
  goto LAB_00016d98;
}

