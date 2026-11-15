
void host_spi_flash_read(void)

{
  undefined1 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint extraout_r2;
  undefined1 uVar5;
  int extraout_r3;
  uint uVar6;
  undefined4 uVar7;
  undefined4 *puVar8;
  bool bVar9;
  uint in_stack_00000000;
  int *in_stack_00000004;
  int in_stack_00000008;
  uint local_44;
  undefined4 local_3a;
  ushort local_36;
  int local_34;
  
  iVar2 = __gnu_mcount_nc();
  iVar3 = DAT_000126c8;
  local_34 = __stack_chk_guard;
  local_36 = 0;
  local_3a = 0;
  if (in_stack_00000000 == 0) {
    local_44 = in_stack_00000000;
  }
  else {
    uVar6 = *(uint *)(iVar2 + 0x14);
    uVar4 = extraout_r3 + (uint)CARRY4(extraout_r2,in_stack_00000000);
    bVar9 = uVar6 <= uVar4;
    if (uVar4 == uVar6) {
      bVar9 = *(uint *)(iVar2 + 0x10) <= extraout_r2 + in_stack_00000000;
    }
    if (bVar9 && (uVar4 != uVar6 || extraout_r2 + in_stack_00000000 != *(uint *)(iVar2 + 0x10))) {
LAB_00010a94:
      local_44 = 0xffffffea;
    }
    else {
      puVar8 = *(undefined4 **)(iVar2 + 0xf4);
      if (in_stack_00000004 != (int *)0x0) {
        *in_stack_00000004 = 0;
      }
      if (iVar3 == 0) {
        uVar7 = 5;
      }
      else {
        uVar7 = 6;
      }
      down(host_spi_flash_lock);
      uVar4 = extraout_r2;
      do {
        iVar3 = FUN_00010488(puVar8);
        if (iVar3 != 0) goto LAB_00010a94;
        if (_LANCHOR2 == 0x1940ef || _LANCHOR2 == 0x19ba20) {
          uVar5 = 0xc;
        }
        else {
          uVar5 = 0xb;
        }
        local_3a = CONCAT31(local_3a._1_3_,uVar5);
        if (puVar8[2] == 0) {
          uVar6 = (*(code *)*puVar8)();
          if (in_stack_00000000 <= uVar6) {
            uVar6 = in_stack_00000000;
          }
          in_stack_00000000 = in_stack_00000000 - uVar6;
        }
        else {
          uVar6 = in_stack_00000000;
          in_stack_00000000 = 0;
        }
        uVar5 = (undefined1)(uVar4 >> 0x10);
        uVar1 = (undefined1)(uVar4 >> 8);
        if (DAT_000126c8 == 0) {
          local_3a._0_2_ = CONCAT11(uVar5,(undefined1)local_3a);
          local_3a = CONCAT13((byte)uVar4,CONCAT12(uVar1,(undefined2)local_3a));
          local_36 = local_36 & 0xff00;
        }
        else {
          local_36 = (ushort)(byte)uVar4;
          local_3a._0_2_ = CONCAT11((char)(uVar4 >> 0x18),(undefined1)local_3a);
          local_3a = CONCAT22(CONCAT11(uVar1,uVar5),(undefined2)local_3a);
        }
        uVar4 = uVar4 + uVar6;
        (*(code *)puVar8[1])(&local_3a,uVar7,in_stack_00000008,uVar6,0);
        in_stack_00000008 = in_stack_00000008 + uVar6;
        *in_stack_00000004 = *in_stack_00000004 + uVar6;
      } while (in_stack_00000000 != 0);
      up(DAT_00010acc);
      local_44 = 0;
    }
  }
  if (local_34 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(local_44);
  }
  return;
}

