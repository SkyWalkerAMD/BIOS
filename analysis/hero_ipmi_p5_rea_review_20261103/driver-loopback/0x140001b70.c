
longlong FUN_140001b70(void)

{
  undefined2 uVar1;
  undefined *puVar2;
  bool bVar3;
  longlong lVar4;
  longlong lVar5;
  undefined7 extraout_var;
  undefined8 uVar6;
  undefined1 *puVar7;
  ulonglong uVar8;
  longlong lVar9;
  longlong local_2e8;
  ulonglong local_2e0;
  ulonglong local_2d8;
  longlong local_2d0;
  ushort local_2c8 [160];
  undefined1 local_188 [328];
  
  lVar9 = DAT_1400570e8;
  lVar5 = -0x7ffffffffffffffa;
  if ((DAT_1400570e8 != 0) && (lVar5 = -0x7ffffffffffffffa, DAT_1400570f8 != 0)) {
    local_2e8 = 0;
    local_2e0 = 0;
    lVar4 = (**(code **)(DAT_1400570f0 + 0x20))(DAT_1400570f0,DAT_1400570e8,&local_2e0,0);
    uVar8 = local_2e0;
    lVar5 = -0x7ffffffffffffffd;
    if ((lVar4 == -0x7ffffffffffffffb) &&
       ((0xffffffffff800016 < local_2e0 - 0x800001 &&
        (lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x40))(4,local_2e0,&local_2e8),
        -1 < lVar5)))) {
      lVar5 = (**(code **)(DAT_1400570f0 + 0x20))(DAT_1400570f0,lVar9,&local_2e0,local_2e8);
      if (-1 < lVar5) {
        if (local_2e0 <= uVar8 && 0x17 < local_2e0) {
          bVar3 = FUN_140001690(local_2e8,local_2e0);
          (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))(local_2e8);
          if ((int)CONCAT71(extraout_var,bVar3) == 0) {
            DAT_1400570e8 = 0;
            return -0x7fffffffffffffdf;
          }
          lVar9 = 0;
          local_2d0 = -0x7ffffffffffffffc;
          do {
            puVar7 = &DAT_1400572e0;
            lVar5 = 0;
            do {
              uVar8 = 2;
              do {
                if (puVar7[uVar8 - 2] == 0) {
                  uVar8 = uVar8 - 2;
                  goto LAB_140001d0a;
                }
                local_2c8[uVar8 - 2] = (ushort)(byte)puVar7[uVar8 - 2];
                if (puVar7[uVar8 - 1] == 0) {
                  uVar8 = uVar8 - 1;
                  goto LAB_140001d0a;
                }
                local_2c8[uVar8 - 1] = (ushort)(byte)puVar7[uVar8 - 1];
                if (puVar7[uVar8] == 0) goto LAB_140001d0a;
                local_2c8[uVar8] = (ushort)(byte)puVar7[uVar8];
                uVar8 = uVar8 + 3;
              } while (uVar8 != 0xa1);
              uVar8 = 0x9f;
LAB_140001d0a:
              local_2c8[uVar8 & 0xffffffff] = 0;
              if ((&DAT_1400572e0)[(uVar8 & 0xffffffff) + lVar5 * 0xa0] != '\0') {
                return local_2d0;
              }
              puVar2 = (&PTR_s_en_US_140055c80)[lVar9];
              uVar1 = (&DAT_140055c30)[lVar5];
              lVar4 = (**(code **)(DAT_1400570f8 + 0x10))
                                (DAT_1400570f8,DAT_1400570e8,uVar1,puVar2,local_2c8,0);
              if (lVar4 < 0) {
                return lVar4;
              }
              local_2d8 = 0x140;
              lVar4 = (**(code **)(DAT_1400570f8 + 8))
                                (DAT_1400570f8,puVar2,DAT_1400570e8,uVar1,local_188,&local_2d8,0);
              if (((lVar4 < 0) || (local_2d8 != (int)uVar8 * 2 + 2)) ||
                 (uVar6 = FUN_140003af0((longlong)local_2c8,(longlong)local_188,local_2d8),
                 (int)uVar6 == 0)) {
                return -0x7ffffffffffffff9;
              }
              lVar5 = lVar5 + 1;
              puVar7 = puVar7 + 0xa0;
            } while (lVar5 != 0x28);
            lVar9 = lVar9 + 1;
            if (lVar9 == 10) {
              FUN_140003b90("P5_NATIVE_STRINGS_PUBLISHED_AND_READ_BACK\r\n");
              return 0;
            }
          } while( true );
        }
        lVar5 = -0x7ffffffffffffff9;
      }
      (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))(local_2e8);
    }
  }
  return lVar5;
}

