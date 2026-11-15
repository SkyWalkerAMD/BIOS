
void PublishParameters_from_event(void)

{
  undefined1 uVar1;
  int iVar2;
  longlong lVar3;
  ulonglong uVar4;
  byte bVar5;
  longlong lVar6;
  undefined8 uVar7;
  char cVar8;
  byte bVar9;
  longlong lVar10;
  undefined7 uVar11;
  byte bVar12;
  byte *pbVar13;
  undefined1 local_res18 [8];
  longlong local_res20;
  longlong local_a8;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  char local_90;
  undefined8 local_8f;
  undefined8 local_87;
  undefined8 local_7f;
  undefined4 local_77;
  undefined2 local_73;
  undefined8 *local_70;
  longlong local_68;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  longlong local_50;
  undefined1 local_48;
  undefined8 local_47;
  undefined8 local_3f;
  undefined8 local_37;
  undefined4 local_2f;
  undefined2 local_2b;
  
  local_res18[0] = 1;
  lVar6 = 0;
  local_8f = 0;
  local_87 = 0;
  local_7f = 0;
  local_77 = 0;
  local_73 = 0;
  local_47 = 0;
  local_3f = 0;
  local_37 = 0;
  local_2f = 0;
  local_2b = 0;
  bVar5 = 0;
  local_90 = '\0';
  local_48 = 0;
  local_60 = 0xbb31e7e8;
  local_5c = 0x43ca94e0;
  local_58 = 0x4c69d0aa;
  local_54 = 0x5cffb3fa;
  local_res20 = 0;
  local_70 = (undefined8 *)0x0;
  lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&DAT_000012e0,0,&local_68);
  if (-1 < lVar3) {
    lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&local_60,0,&local_res20);
    if ((lVar3 < 0) || (*(char *)(local_res20 + 1) != '\x02')) {
      *(undefined1 *)(local_res20 + 2) = 1;
      lVar10 = 0x21;
      *(undefined1 *)(local_res20 + 0x1d) = 0;
      *(undefined1 *)(local_res20 + 0x1e) = 0;
      *(undefined1 *)(local_res20 + 0x1f) = 0;
      *(undefined1 *)(local_res20 + 0x30) = 0;
      *(undefined1 *)(local_res20 + 0x31) = 1;
      *(undefined1 *)(local_res20 + 0x20) = 1;
      *(undefined1 *)(local_res20 + 0x21) = 0;
      *(undefined1 *)(local_res20 + 0x22) = 0;
      *(undefined1 *)(local_res20 + 0x23) = 1;
      *(undefined1 *)(local_res20 + 0x24) = 0;
      *(undefined1 *)(local_res20 + 0x52) = 0;
      lVar3 = lVar6;
      do {
        *(undefined1 *)(lVar3 + 8 + local_res20) = 0;
        lVar3 = lVar3 + 1;
        lVar10 = lVar10 + -1;
      } while (lVar10 != 0);
      lVar3 = 0x26;
      lVar10 = 5;
      do {
        *(undefined2 *)(lVar3 + local_res20) = 0;
        lVar3 = lVar3 + 2;
        lVar10 = lVar10 + -1;
      } while (lVar10 != 0);
      lVar10 = 0x20;
      lVar3 = lVar6;
      do {
        *(undefined1 *)(lVar3 + 0x32 + local_res20) = 0;
        lVar3 = lVar3 + 1;
        lVar10 = lVar10 + -1;
      } while (lVar10 != 0);
      lVar3 = 0xf;
      do {
        *(undefined1 *)(lVar6 + 0x53 + local_res20) = 0;
        *(undefined1 *)(lVar6 + 0x62 + local_res20) = 0;
        *(undefined1 *)(lVar6 + 0x71 + local_res20) = 0;
        lVar6 = lVar6 + 1;
        lVar3 = lVar3 + -1;
      } while (lVar3 != 0);
    }
    local_90 = *(char *)(local_res20 + 0x31);
    (**(code **)(local_68 + 8))(local_68,0x30,0,0x90,&local_90,1,&local_48,local_res18);
    if (*(char *)(local_res20 + 0x32) != '\0') {
      cVar8 = *(char *)(local_res20 + 0x32);
      uVar4 = 0;
      bVar12 = bVar5;
      do {
        bVar12 = bVar12 + 1;
        bVar5 = (char)uVar4 + 2;
        (&local_90)[uVar4] = cVar8;
        *(undefined1 *)((longlong)&local_8f + uVar4) = 1;
        cVar8 = *(char *)((ulonglong)bVar12 + 0x32 + local_res20);
        uVar4 = (ulonglong)bVar5;
      } while (cVar8 != '\0');
    }
    (**(code **)(local_68 + 8))(local_68,0x30,0,0x94,&local_90,bVar5,&local_48,local_res18);
    if ((*(char *)(local_res20 + 0x30) == '\0') &&
       (lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&DAT_000012b0,0,&local_70), -1 < lVar3)) {
      iVar2 = (*(code *)*local_70)(*(undefined2 *)(local_res20 + 0x26));
      local_90 = '\x01';
      if (iVar2 < 1) {
        local_8f = (ulonglong)local_8f._1_7_ << 8;
      }
      else {
        uVar1 = (undefined1)iVar2;
        if (0xff < iVar2) {
          uVar1 = 0xff;
        }
        local_8f = CONCAT71(local_8f._1_7_,uVar1);
      }
      lVar3 = 2;
      if (*(char *)(local_res20 + 0x21) == '\x01') {
        iVar2 = (*(code *)*local_70)(*(undefined2 *)(local_res20 + 0x28));
        lVar3 = local_8f;
        local_8f._0_2_ = CONCAT11(2,(undefined1)local_8f);
        local_8f._3_5_ = SUB85(lVar3,3);
        if (iVar2 < 1) {
          local_8f._0_3_ = (uint3)(ushort)local_8f;
        }
        else {
          uVar1 = (undefined1)iVar2;
          if (0xff < iVar2) {
            uVar1 = 0xff;
          }
          local_8f._0_3_ = CONCAT12(uVar1,(ushort)local_8f);
        }
        lVar3 = 4;
      }
      bVar5 = (byte)lVar3;
      if (*(char *)(local_res20 + 0x22) == '\x01') {
        iVar2 = (*(code *)*local_70)(*(undefined2 *)(local_res20 + 0x2a));
        (&local_90)[lVar3] = '\x03';
        if (iVar2 < 1) {
          *(undefined1 *)((longlong)&local_8f + lVar3) = 0;
        }
        else {
          uVar1 = (undefined1)iVar2;
          if (0xff < iVar2) {
            uVar1 = 0xff;
          }
          *(undefined1 *)((longlong)&local_8f + lVar3) = uVar1;
        }
        bVar5 = bVar5 + 2;
      }
      iVar2 = (*(code *)*local_70)(*(undefined2 *)(local_res20 + 0x2c));
      bVar12 = bVar5 + 2;
      iVar2 = iVar2 / 100;
      (&local_90)[bVar5] = '\x1e';
      *(char *)((longlong)&local_8f + (ulonglong)bVar5) = (char)iVar2;
      if (*(char *)(local_res20 + 0x24) == '\x01') {
        iVar2 = (*(code *)*local_70)(*(undefined2 *)(local_res20 + 0x2e));
        (&local_90)[bVar12] = '\x1f';
        iVar2 = iVar2 / 100;
        uVar4 = (ulonglong)bVar12;
        bVar12 = bVar5 + 4;
        *(char *)((longlong)&local_8f + uVar4) = (char)iVar2;
      }
      (**(code **)(local_68 + 8))
                (local_68,CONCAT71((uint7)(uint3)((uint)iVar2 >> 8),0x30),0,0x91,&local_90,bVar12,
                 &local_48,local_res18);
    }
    local_90 = *(char *)(local_res20 + 0x1e);
    local_8f = CONCAT71(local_8f._1_7_,*(undefined1 *)(local_res20 + 0x1d));
    (**(code **)(local_68 + 8))(local_68,0x30,0,0x92,&local_90,2,&local_48,local_res18);
    if (*(char *)(local_res20 + 0x52) == '\x01') {
      if (DAT_000013d0 != '\0') {
        FUN_000008dc();
      }
      local_a8 = 0;
      local_a0 = 0xbb31e7e8;
      bVar5 = 0;
      local_9c = 0x43ca94e0;
      bVar12 = 0;
      local_98 = 0x4c69d0aa;
      local_94 = 0x5cffb3fa;
      lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&local_a0,0,&local_50);
      if ((-1 < lVar3) &&
         (lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&DAT_000012c0,0,&local_a8), -1 < lVar3)) {
        uVar4 = 0;
        (**(code **)(local_a8 + 0x10))(0xff,0);
        uVar4 = uVar4 & 0xffffffffffffff00;
        do {
          if (*(char *)((uVar4 & 0xff) + 0x62 + local_50) != '\0') {
            lVar3 = 0xf;
            pbVar13 = (byte *)(local_50 + 0x62);
            uVar4 = CONCAT71((int7)(uVar4 >> 8),0xf);
            do {
              bVar9 = *pbVar13;
              if (bVar9 < 7) {
                if (bVar9 == 6) {
                  bVar5 = bVar5 | 0x20;
                }
                else if (bVar9 == 1) {
                  bVar5 = bVar5 | 1;
                }
                else if (bVar9 == 2) {
                  bVar5 = bVar5 | 2;
                }
                else if (bVar9 == 3) {
                  bVar5 = bVar5 | 4;
                }
                else if (bVar9 == 4) {
                  bVar5 = bVar5 | 8;
                }
                else if (bVar9 == 5) {
                  bVar5 = bVar5 | 0x10;
                }
              }
              else if (bVar9 == 7) {
                bVar5 = bVar5 | 0x40;
              }
              else if (bVar9 == 0xb) {
                bVar12 = bVar12 | 4;
              }
              else if (bVar9 == 0xc) {
                bVar12 = bVar12 | 8;
              }
              else if (bVar9 == 0xd) {
                bVar12 = bVar12 | 0x10;
              }
              pbVar13 = pbVar13 + 1;
              lVar3 = lVar3 + -1;
            } while (lVar3 != 0);
          }
          uVar11 = (undefined7)(uVar4 >> 8);
          bVar9 = (char)uVar4 + 1;
          uVar4 = CONCAT71(uVar11,bVar9);
        } while (bVar9 < 0xf);
        if (*(char *)(local_50 + 2) == '\x02') {
          (**(code **)(local_a8 + 0x10))(0x86);
          (**(code **)(local_a8 + 0x10))(0x87,bVar5);
          uVar7 = 0x84;
        }
        else {
          (**(code **)(local_a8 + 0x10))(0x92,CONCAT71(uVar11,bVar12));
          (**(code **)(local_a8 + 0x10))(0x93,bVar5);
          uVar7 = 0x90;
        }
        (**(code **)(local_a8 + 0x10))(uVar7,0);
        (**(code **)(local_a8 + 0x10))(0xff,0);
      }
    }
    local_90 = '\x01';
    (**(code **)(local_68 + 8))(local_68,0x30,0,2,&local_90,1,&local_48,local_res18);
    if (*(char *)(local_res20 + 0x52) == '\x01') {
      local_a8 = 0;
      local_a0 = 0xbb31e7e8;
      local_9c = 0x43ca94e0;
      local_98 = 0x4c69d0aa;
      local_94 = 0x5cffb3fa;
      lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&DAT_000012c0,0,&local_a8);
      if (-1 < lVar3) {
        (**(code **)(local_a8 + 0x10))(0xff,0);
        lVar3 = (**(code **)(DAT_000013d8 + 0x140))(&local_a0,0,&local_50);
        if ((-1 < lVar3) && (*(char *)(local_50 + 0x1f) != '\0')) {
          uVar7 = 0x84;
          if (*(char *)(local_50 + 2) != '\x02') {
            uVar7 = 0x90;
          }
          (**(code **)(local_a8 + 0x10))(uVar7,1);
        }
        (**(code **)(local_a8 + 0x10))(0xff,0);
      }
    }
  }
  return;
}

