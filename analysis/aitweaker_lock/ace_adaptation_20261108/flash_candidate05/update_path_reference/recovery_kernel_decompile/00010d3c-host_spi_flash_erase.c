
void host_spi_flash_erase(void)

{
  undefined1 uVar1;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  uint *puVar7;
  int extraout_r1;
  int extraout_r1_00;
  int extraout_r1_01;
  int extraout_r1_02;
  char cVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  bool bVar15;
  undefined8 uVar16;
  undefined4 local_44;
  undefined4 local_39;
  undefined1 local_35;
  int local_34;
  undefined1 uVar2;
  
  uVar16 = __gnu_mcount_nc();
  puVar7 = (uint *)((ulonglong)uVar16 >> 0x20);
  uVar10 = *(uint *)((int)uVar16 + 0x10);
  uVar11 = *(uint *)((int)uVar16 + 0x14);
  uVar13 = puVar7[2];
  uVar14 = puVar7[3];
  uVar4 = *puVar7;
  uVar9 = puVar7[1] + uVar14 + (uint)CARRY4(uVar4,uVar13);
  bVar15 = uVar11 <= uVar9;
  if (uVar9 == uVar11) {
    bVar15 = uVar10 <= uVar4 + uVar13;
  }
  local_34 = __stack_chk_guard;
  if (!bVar15 || uVar9 == uVar11 && uVar4 + uVar13 == uVar10) {
    if (uVar14 == 0 && uVar13 < 0x8000) {
      iVar12 = 0x1000;
    }
    else {
      uVar9 = *(uint *)(g_spi_info + 0x10);
      if (((uint)(uVar14 == 0 && uVar13 < 0x10000) & uVar9 >> 1) == 0) {
        if ((uVar9 & 4) == 0) {
          if ((uVar9 & 2) == 0) {
            iVar12 = 0x1000;
          }
          else {
            iVar12 = 0x8000;
          }
        }
        else {
          iVar12 = 0x10000;
        }
      }
      else {
        iVar12 = 0x8000;
      }
    }
    if (puVar7[1] == 0) {
      __aeabi_uidivmod(uVar4,iVar12);
      iVar5 = extraout_r1;
    }
    else {
      __do_div64();
      iVar5 = extraout_r1_01;
    }
    if (iVar5 == 0) {
      if (uVar14 == 0) {
        __aeabi_uidivmod(uVar13,iVar12);
        iVar5 = extraout_r1_00;
      }
      else {
        __do_div64(uVar13,uVar14);
        iVar5 = extraout_r1_02;
      }
      if (iVar5 == 0) {
        uVar4 = *puVar7;
        uVar9 = puVar7[2];
        down(host_spi_flash_lock);
        uVar6 = DAT_0001109c;
        if (iVar12 == 0x8000) {
          if (DAT_000126c8 == 0) {
            cVar8 = 'R';
          }
          else {
            cVar8 = '\\';
          }
LAB_00010f04:
          if (_LANCHOR2 == 0x481f) goto LAB_00011034;
          if (DAT_000126c8 != 0 && cVar8 == -0x28) {
LAB_00010ea0:
            enter_4byte_addr_mode(DAT_0001109c);
            cVar8 = -0x28;
            uVar6 = DAT_0001109c;
          }
        }
        else {
          if (iVar12 != 0x10000) {
            if (iVar12 != 0x1000) {
              printk("[%s]Invalid Erase Block Size\n",DAT_000110a0);
              uVar6 = 0xffffffff;
              goto LAB_00010ecc;
            }
            if (DAT_000126c8 == 0) {
              cVar8 = ' ';
            }
            else {
              cVar8 = '!';
            }
            goto LAB_00010f04;
          }
          if (DAT_000126c8 == 0) {
            cVar8 = -0x28;
            goto LAB_00010f04;
          }
          if (_LANCHOR2 != 0x1940ef && _LANCHOR2 != 0x19ba20) {
            cVar8 = -0x24;
            goto LAB_00010f04;
          }
          if (_LANCHOR2 != 0x481f) goto LAB_00010ea0;
LAB_00011034:
          cVar8 = '9';
        }
        for (; uVar3 = DAT_0001109c, DAT_0001109c = uVar6, uVar9 != 0; uVar9 = uVar9 - iVar12) {
          local_39 = 0;
          local_35 = 0;
          iVar5 = FUN_00010488(uVar3);
          if (iVar5 != 0) {
LAB_00011014:
            uVar6 = DAT_000110a4;
            puVar7[4] = uVar4;
            puVar7[5] = 0;
            up(uVar6);
            uVar6 = 0xfffffffb;
            goto LAB_00010ecc;
          }
          uVar1 = (undefined1)(uVar4 >> 0x10);
          uVar2 = (undefined1)(uVar4 >> 8);
          if (DAT_000126c8 == 0) {
            local_44 = 4;
            local_39 = CONCAT13((char)uVar4,CONCAT21(CONCAT11(uVar2,uVar1),cVar8));
          }
          else {
            local_44 = 5;
            local_39 = CONCAT22(CONCAT11(uVar2,uVar1),CONCAT11((char)(uVar4 >> 0x18),cVar8));
            local_35 = (char)uVar4;
          }
          FUN_00010548(uVar3,1);
          (*(code *)spi_flash_ops._4_4_)(&local_39,local_44,0,0,0);
          iVar5 = FUN_00010488(uVar3);
          if (iVar5 != 0) goto LAB_00011014;
          uVar4 = uVar4 + iVar12;
          uVar6 = DAT_0001109c;
          DAT_0001109c = uVar3;
        }
        up(DAT_000110a4);
        uVar6 = 0;
        goto LAB_00010ecc;
      }
    }
  }
  uVar6 = 0xffffffea;
LAB_00010ecc:
  if (local_34 == __stack_chk_guard) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar6);
}

