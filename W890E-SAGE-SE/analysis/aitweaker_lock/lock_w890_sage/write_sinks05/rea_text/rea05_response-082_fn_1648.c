
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_00001648(undefined8 param_1,undefined8 param_2)

{
  char cVar1;
  char cVar2;
  char cVar3;
  char cVar4;
  longlong lVar5;
  wchar_t *pwVar6;
  ulonglong uVar7;
  undefined7 uVar10;
  ushort *puVar8;
  undefined8 *puVar9;
  byte *pbVar11;
  char cVar12;
  undefined8 local_res8;
  byte local_res10;
  undefined7 uStackX_11;
  undefined4 local_res18 [2];
  undefined8 local_res20;
  undefined8 local_168;
  undefined8 uStack_160;
  undefined8 local_158;
  undefined8 uStack_150;
  undefined8 local_148;
  undefined8 uStack_140;
  undefined8 local_138;
  undefined8 uStack_130;
  ushort local_128 [40];
  ushort local_d8 [40];
  ushort local_88 [40];
  
  cVar12 = '\0';
  uStackX_11 = (undefined7)((ulonglong)param_2 >> 8);
  _local_res10 = CONCAT71(uStackX_11,2);
  local_res8 = param_1;
  lVar5 = (**(code **)(DAT_00003088 + 0x140))(&DAT_00003010,0,&DAT_000034a8);
  if (-1 < lVar5) {
    local_res20 = 0x401;
    pwVar6 = u_ServerSetup_00003030;
    lVar5 = (**(code **)(DAT_00003090 + 0x48))
                      (u_ServerSetup_00003030,&DAT_00003020,local_res18,&local_res20,&DAT_000030a0);
    if (lVar5 < 0) {
      pwVar6 = (wchar_t *)&DAT_000030a0;
      FUN_00002180(&DAT_000030a0);
    }
    cVar1 = DAT_000031c3;
    cVar2 = DAT_000031c4;
    cVar3 = DAT_000032b8;
    cVar4 = DAT_000032b9;
    lVar5 = FUN_00002014((ulonglong)pwVar6,(char *)&local_res8,&local_res10);
    if (-1 < lVar5) {
      if ((char)local_res8 != '\0') {
        pbVar11 = &local_res10;
        _local_res10 = CONCAT71(uStackX_11,DAT_000031c1);
        uVar7 = CONCAT71((int7)((ulonglong)pwVar6 >> 8),(char)local_res8);
        lVar5 = FUN_000013fc(uVar7,pbVar11);
        uVar10 = (undefined7)(uVar7 >> 8);
        pwVar6 = (wchar_t *)CONCAT71(uVar10,local_res10);
        DAT_000031c1 = local_res10;
        cVar12 = '\0';
        if ((-1 < lVar5) && (local_res10 == 1)) {
          _DAT_000031c3 = 0;
          if (cVar2 == '\x01') {
            cVar12 = '\x01';
          }
          else {
            cVar12 = '\0';
            if (cVar2 == '\x02') {
              cVar12 = '\x02';
            }
          }
          if (cVar1 != '\0') {
            if (cVar1 == '\x01') {
              FUN_00001000((undefined8 *)local_128,(undefined8 *)&DAT_00003266,0x50);
              puVar8 = local_128;
              FUN_00001d8c(puVar8,&local_168);
              pwVar6 = (wchar_t *)CONCAT71((int7)((ulonglong)puVar8 >> 8),(char)local_res8);
              local_158 = local_168;
              uStack_150 = uStack_160;
              FUN_000011ec((undefined8 *)pwVar6,&local_158,DAT_000031c2);
            }
            else {
              pwVar6 = (wchar_t *)CONCAT71(uVar10,(char)local_res8);
              FUN_0000108c((ulonglong)pwVar6,
                           CONCAT71((int7)((ulonglong)pbVar11 >> 8),cVar1 == '\x01'));
            }
          }
          if (cVar2 != '\0') {
            pwVar6 = (wchar_t *)CONCAT71((int7)((ulonglong)pwVar6 >> 8),(char)local_res8);
            FUN_00001188((ulonglong)pwVar6,cVar12);
            if (cVar12 == '\x01') {
              FUN_00001000((undefined8 *)local_d8,(undefined8 *)&DAT_000031c6,0x50);
              FUN_00001d8c(local_d8,&local_168);
              FUN_00001000((undefined8 *)local_88,(undefined8 *)&DAT_00003216,0x50);
              puVar8 = local_88;
              FUN_00001d8c(puVar8,&local_138);
              pwVar6 = (wchar_t *)CONCAT71((int7)((ulonglong)puVar8 >> 8),(char)local_res8);
              local_158 = local_138;
              uStack_150 = uStack_130;
              local_148 = local_168;
              uStack_140 = uStack_160;
              FUN_00001288((undefined8 *)pwVar6,&local_148,&local_158,DAT_000031c5);
            }
          }
        }
        if (DAT_000033ab != 2) {
          pwVar6 = (wchar_t *)CONCAT71((int7)((ulonglong)pwVar6 >> 8),(char)local_res8);
          FUN_000014a4((ulonglong)pwVar6,DAT_000033ab,(ushort)((uint)_DAT_000033ab >> 0x10),
                       DAT_000033ac);
          _DAT_000033ab = 2;
        }
      }
      uVar7 = CONCAT71((int7)((ulonglong)pwVar6 >> 8),local_res8._1_1_);
      if (local_res8._1_1_ != '\0') {
        pbVar11 = &local_res10;
        _local_res10 = CONCAT71(uStackX_11,DAT_000032b6);
        lVar5 = FUN_000013fc(uVar7,pbVar11);
        uVar10 = (undefined7)(uVar7 >> 8);
        puVar9 = (undefined8 *)CONCAT71(uVar10,local_res10);
        DAT_000032b6 = local_res10;
        if ((-1 < lVar5) && (local_res10 == 1)) {
          _DAT_000032b8 = 0;
          if (cVar4 == '\x01') {
            cVar12 = '\x01';
          }
          else if (cVar4 == '\x02') {
            cVar12 = '\x02';
          }
          if (cVar3 != '\0') {
            if (cVar3 == '\x01') {
              FUN_00001000((undefined8 *)local_128,(undefined8 *)&DAT_0000330b,0x50);
              puVar8 = local_128;
              FUN_00001d8c(puVar8,&local_168);
              puVar9 = (undefined8 *)CONCAT71((int7)((ulonglong)puVar8 >> 8),local_res8._1_1_);
              local_148 = local_168;
              uStack_140 = uStack_160;
              FUN_000011ec(puVar9,&local_148,DAT_000032b7);
            }
            else {
              puVar9 = (undefined8 *)CONCAT71(uVar10,local_res8._1_1_);
              FUN_0000108c((ulonglong)puVar9,
                           CONCAT71((int7)((ulonglong)pbVar11 >> 8),cVar3 == '\x01'));
            }
          }
          if (cVar4 != '\0') {
            puVar9 = (undefined8 *)CONCAT71((int7)((ulonglong)puVar9 >> 8),local_res8._1_1_);
            FUN_00001188((ulonglong)puVar9,cVar12);
            if (cVar12 == '\x01') {
              FUN_00001000((undefined8 *)local_d8,(undefined8 *)&DAT_000032bb,0x50);
              FUN_00001d8c(local_d8,&local_168);
              FUN_00001000((undefined8 *)local_88,(undefined8 *)&DAT_0000335b,0x50);
              puVar8 = local_88;
              FUN_00001d8c(puVar8,&local_138);
              puVar9 = (undefined8 *)CONCAT71((int7)((ulonglong)puVar8 >> 8),local_res8._1_1_);
              local_148 = local_138;
              uStack_140 = uStack_130;
              local_158 = local_168;
              uStack_150 = uStack_160;
              FUN_00001288(puVar9,&local_158,&local_148,DAT_000032ba);
            }
          }
        }
        if (DAT_000033af != 2) {
          FUN_000014a4(CONCAT71((int7)((ulonglong)puVar9 >> 8),local_res8._1_1_),DAT_000033af,
                       (ushort)((uint)_DAT_000033af >> 0x10),DAT_000033b0);
          _DAT_000033af = 2;
        }
      }
      (**(code **)(DAT_00003090 + 0x58))
                (u_ServerSetup_00003030,&DAT_00003020,local_res18[0],0x401,&DAT_000030a0);
      lVar5 = 0;
    }
  }
  return lVar5;
}

