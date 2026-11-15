
longlong FUN_000033dc(longlong param_1,longlong param_2,ulonglong param_3,ulonglong param_4)

{
  char cVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  longlong lVar4;
  ulonglong uVar5;
  undefined8 *puVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong lVar12;
  undefined8 *puVar13;
  uint *puVar14;
  longlong lStack0000000000000028;
  ulonglong local_68;
  longlong local_60;
  undefined8 *local_58;
  longlong local_50;
  ulonglong local_48;
  longlong local_40;
  
  uVar2 = param_4 & 0xff;
  lStack0000000000000028 = 0;
  uVar3 = (*(code *)(&PTR_LAB_0000a290)[uVar2 * 6])();
  lVar4 = (**(code **)(DAT_0000b2f8 + 0x50))(6,uVar3,&stack0x00000028);
  if (-1 < lVar4) {
    local_68 = 0x1000;
    if ((DAT_0000b2c8 != (undefined8 *)0x0) ||
       (lVar4 = (**(code **)(DAT_0000b2f8 + 0x50))(6,0x1000,&DAT_0000b2c8), -1 < lVar4)) {
      lVar4 = -0x7fffffffffffffe6;
      lVar12 = (ulonglong)*(ushort *)(param_1 + 0x1e) + param_1;
      uVar8 = ((ulonglong)*(ushort *)(param_1 + 0x1c) - (ulonglong)*(ushort *)(param_1 + 0x1e)) /
              0x18;
      local_48 = uVar8;
      local_40 = lVar12;
      cVar1 = (*(code *)(&PTR_LAB_0000a298)[uVar2 * 6])();
      if ((cVar1 != '\0') && (uVar7 = 0, uVar8 != 0)) {
        puVar14 = (uint *)(lVar12 + 0xc);
        uVar9 = local_68;
        do {
          if (*puVar14 == 0) break;
          uVar10 = (ulonglong)puVar14[-1];
          if (param_3 < uVar10) goto LAB_000036fd;
          uVar11 = uVar10 + *puVar14;
          if (param_3 < uVar11) goto LAB_000036fd;
          uVar5 = uVar10 / uVar9;
          uVar11 = uVar11 - uVar5 * uVar9;
          local_58 = (undefined8 *)(uVar5 * uVar9 + param_2);
          lVar12 = (ulonglong)(uVar11 % uVar9 != 0) + uVar11 / uVar9;
          uVar11 = (lVar12 + uVar5) * uVar9;
          if ((param_3 <= uVar11 && uVar11 - param_3 != 0) || (0x4000 < lVar12 + uVar5))
          goto LAB_000036fd;
          puVar13 = (undefined8 *)(param_2 + uVar10);
          if (lVar12 != 0) {
            local_60 = uVar5 << 5;
            local_50 = lVar12;
            uVar10 = (ulonglong)*puVar14;
            do {
              local_50 = local_50 + -1;
              if ((uVar9 != 0) && (DAT_0000b2c8 != local_58)) {
                FUN_00001180(DAT_0000b2c8,local_58,uVar9);
              }
              lVar12 = (**(code **)(DAT_0000b5f8 + 0x10))
                                 (DAT_0000b5f8,&DAT_0000a020,1,&DAT_0000b2c8,&local_68,
                                  DAT_0000b280 + local_60);
              local_60 = local_60 + 0x20;
              if (lVar12 < 0) goto LAB_000036fd;
              uVar11 = uVar10;
              if ((puVar14[2] & 0x200) != 0) {
                puVar6 = (undefined8 *)
                         (((longlong)DAT_0000b2c8 - (longlong)local_58) + (longlong)puVar13);
                if (local_68 < uVar10) {
                  uVar8 = (longlong)local_58 + (local_68 - (longlong)puVar13);
                  uVar11 = uVar10 - uVar8;
                }
                else {
                  if ((uVar10 != 0) && (DAT_0000b2c8 != puVar13)) {
                    FUN_00001180(DAT_0000b2c8,puVar13,uVar10);
                  }
                  uVar11 = 0;
                  puVar6 = DAT_0000b2c8;
                  uVar8 = uVar10;
                }
                cVar1 = (*(code *)(&PTR_FUN_0000a2a0)[uVar2 * 6])
                                  (lStack0000000000000028,puVar6,uVar8);
                if (cVar1 == '\0') goto LAB_000036fd;
                puVar13 = (undefined8 *)((longlong)puVar13 + uVar8);
              }
              local_58 = (undefined8 *)((longlong)local_58 + local_68);
              uVar8 = local_48;
              uVar9 = local_68;
              uVar10 = uVar11;
            } while (local_50 != 0);
          }
          uVar7 = uVar7 + 1;
          puVar14 = puVar14 + 6;
        } while (uVar7 < uVar8);
        if ((((uVar7 != 0) && (uVar7 < uVar8)) &&
            (((*(byte *)(param_1 + 0x14) & 2) == 0 ||
             (cVar1 = (*(code *)(&PTR_FUN_0000a2a0)[uVar2 * 6])(lStack0000000000000028,param_1,0x38)
             , cVar1 != '\0')))) &&
           (cVar1 = (*(code *)(&PTR_FUN_0000a2a0)[uVar2 * 6])
                              (lStack0000000000000028,local_40,(uVar7 + 1) * 0x18), cVar1 != '\0'))
        {
          cVar1 = (*(code *)(&PTR_LAB_0000a2a8)[uVar2 * 6])(lStack0000000000000028,&DAT_0000b530);
          if (cVar1 != '\0') {
            lVar4 = 0;
          }
        }
      }
    }
LAB_000036fd:
    if (lStack0000000000000028 != 0) {
      (**(code **)(DAT_0000b2f8 + 0x58))();
    }
  }
  return lVar4;
}

