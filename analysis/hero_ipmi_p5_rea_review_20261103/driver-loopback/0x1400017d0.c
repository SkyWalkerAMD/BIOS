
longlong FUN_1400017d0(void)

{
  undefined *puVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  bool bVar4;
  longlong lVar5;
  longlong lVar6;
  undefined7 extraout_var;
  int iVar7;
  longlong lVar8;
  undefined8 uVar9;
  ulonglong uVar10;
  ulonglong local_1a0;
  longlong local_198;
  undefined8 local_190;
  longlong local_188 [41];
  
  lVar8 = -0x7ffffffffffffff2;
  DAT_1400570e8 = 0;
  lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x140))
                    (&DAT_140057030,0,&DAT_1400570f0);
  if ((((-1 < lVar5) && (DAT_1400570f0 != 0)) &&
      (lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x140))
                         (&DAT_140057040,0,&DAT_1400570f8), -1 < lVar5)) && (DAT_1400570f8 != 0)) {
    local_190 = 0;
    lVar5 = (**(code **)(DAT_1400570f0 + 0x18))(DAT_1400570f0,2,0,&local_190,0);
    uVar10 = local_190;
    if ((local_190 != 0 && lVar5 == -0x7ffffffffffffffb) &&
       (local_190 < 0x8001 && (local_190 & 7) == 0)) {
      local_198 = 0;
      lVar8 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x40))(4,local_190,&local_198);
      if (-1 < lVar8) {
        lVar8 = (**(code **)(DAT_1400570f0 + 0x18))(DAT_1400570f0,2,0,&local_190,local_198);
        if (-1 < lVar8) {
          if ((local_190 & 7) == 0 && local_190 <= uVar10) {
            if (local_190 < 8) {
              iVar7 = 0;
              uVar9 = 0;
            }
            else {
              uVar10 = 0;
              uVar9 = 0;
              iVar7 = 0;
              do {
                uVar2 = *(undefined8 *)(local_198 + uVar10 * 8);
                local_188[0] = 0;
                local_1a0 = 0;
                lVar5 = (**(code **)(DAT_1400570f0 + 0x20))(DAT_1400570f0,uVar2,&local_1a0,0);
                uVar3 = local_1a0;
                if (((lVar5 == -0x7ffffffffffffffb) && (0xffffffffff800016 < local_1a0 - 0x800001))
                   && (lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x40))
                                         (4,local_1a0,local_188), -1 < lVar5)) {
                  lVar5 = (**(code **)(DAT_1400570f0 + 0x20))(DAT_1400570f0,uVar2,&local_1a0);
                  if (((-1 < lVar5) && (local_1a0 <= uVar3 && 0x17 < local_1a0)) &&
                     (bVar4 = FUN_140001690(local_188[0],local_1a0),
                     (int)CONCAT71(extraout_var,bVar4) != 0)) {
                    uVar9 = *(undefined8 *)(local_198 + uVar10 * 8);
                    iVar7 = iVar7 + 1;
                  }
                  (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))(local_188[0]);
                }
                uVar10 = uVar10 + 1;
              } while (uVar10 < local_190 >> 3);
            }
            (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))(local_198);
            if (iVar7 == 1) {
              lVar5 = 0;
              do {
                puVar1 = (&PTR_s_en_US_140055c80)[lVar5];
                lVar8 = 0;
                do {
                  local_1a0 = 0x140;
                  lVar6 = (**(code **)(DAT_1400570f8 + 8))
                                    (DAT_1400570f8,puVar1,uVar9,
                                     *(undefined2 *)((longlong)&DAT_140055c30 + lVar8),local_188,
                                     &local_1a0,0);
                  if (((lVar6 < 0) || (0x13e < local_1a0 - 2)) ||
                     (((local_1a0 & 1) != 0 ||
                      (*(short *)((local_1a0 - 2) + (longlong)local_188) != 0)))) {
                    return -0x7fffffffffffffdf;
                  }
                  lVar8 = lVar8 + 2;
                } while (lVar8 != 0x50);
                lVar5 = lVar5 + 1;
                if (lVar5 == 10) {
                  DAT_1400570e8 = uVar9;
                  return 0;
                }
              } while( true );
            }
            if (iVar7 == 0) {
              return -0x7ffffffffffffff2;
            }
            return -0x7ffffffffffffff1;
          }
          lVar8 = -0x7ffffffffffffff9;
        }
        (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))(local_198);
      }
    }
  }
  return lVar8;
}

