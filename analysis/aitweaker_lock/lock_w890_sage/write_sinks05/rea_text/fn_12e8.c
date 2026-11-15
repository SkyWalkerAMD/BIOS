
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong WS05_12e8(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  char cVar2;
  longlong lVar3;
  wchar_t *pwVar4;
  undefined8 *puVar5;
  byte bVar6;
  undefined8 local_res8;
  byte local_res10;
  undefined7 uStackX_11;
  undefined4 local_res18 [2];
  undefined8 local_res20;
  undefined1 auStack_97 [8];
  undefined4 uStack_8f;
  undefined1 auStack_8b [5];
  undefined1 local_86;
  byte local_80;
  undefined1 auStack_7f [8];
  undefined4 uStack_77;
  undefined1 auStack_73 [5];
  undefined1 local_6e;
  undefined8 local_68;
  undefined8 uStack_60;
  undefined2 local_58;
  undefined1 local_56;
  
  _local_res10 = CONCAT71((int7)((ulonglong)param_2 >> 8),2);
  local_res8 = param_1;
  lVar3 = (**(code **)(DAT_00002088 + 0x140))(&DAT_00002010,0,&DAT_000024a8);
  if (-1 < lVar3) {
    puVar5 = &local_res8;
    FUN_00001040(puVar5,2);
    lVar3 = FUN_00001a30((ulonglong)puVar5,(char *)&local_res8,&local_res10);
    if (-1 < lVar3) {
      local_res20 = 0x401;
      lVar3 = (**(code **)(DAT_00002090 + 0x48))
                        (u_ServerSetup_00002030,&DAT_00002020,local_res18,&local_res20,&DAT_000020a0
                        );
      if (lVar3 < 0) {
        FUN_00001b9c(&DAT_000020a0);
      }
      bVar6 = DAT_00002144;
      bVar1 = DAT_000020c7;
      local_80 = DAT_00002144;
      if ((char)local_res8 != '\0') {
        DAT_000020c7 = 0;
        lVar3 = FUN_00001700((undefined4 *)auStack_97,(short *)&DAT_000020c8);
        if (lVar3 != 0) {
          _DAT_000020c8 = 0x2e002e;
          _DAT_000020cc = 0x2e;
          _DAT_000020d4 = 0;
          _DAT_000020dc = 0;
          _DAT_000020e4 = 0;
        }
        lVar3 = FUN_00001700((undefined4 *)(auStack_97 + 4),(short *)&DAT_000020e6);
        if (lVar3 != 0) {
          _DAT_000020e6 = 0x2e002e;
          _DAT_000020ea = 0x2e;
          _DAT_000020f2 = 0;
          _DAT_000020fa = 0;
          _DAT_00002102 = 0;
        }
        lVar3 = FUN_00001700(&uStack_8f,(short *)&DAT_00002104);
        if (lVar3 != 0) {
          _DAT_00002104 = 0x2e0030;
          _DAT_00002108 = 0x2e0030;
          _DAT_0000210c = 0x2e0030;
          _DAT_00002110 = 0x30;
          _DAT_00002118 = 0;
          _DAT_00002120 = 0;
        }
        lVar3 = FUN_0000185c((undefined4 *)auStack_8b,0x2122);
        if (lVar3 != 0) {
          _DAT_00002122 = 0x300030;
          _DAT_00002126 = 0x30002d;
          _DAT_0000212a = 0x2d0030;
          _DAT_0000212e = 0x300030;
          _DAT_00002132 = 0x30002d;
          _DAT_00002136 = 0x2d0030;
          _DAT_0000213a = 0x300030;
          _DAT_0000213e = 0x30002d;
          _DAT_00002142 = 0x30;
        }
      }
      if (local_res8._1_1_ != '\0') {
        DAT_00002144 = 0;
        lVar3 = FUN_00001700((undefined4 *)auStack_7f,(short *)&DAT_00002145);
        if (lVar3 != 0) {
          _DAT_00002145 = 0x2e002e;
          _DAT_00002149 = 0x2e;
          _DAT_00002151 = 0;
          _DAT_00002159 = 0;
          _DAT_00002161 = 0;
        }
        lVar3 = FUN_00001700((undefined4 *)(auStack_7f + 4),(short *)&DAT_00002163);
        if (lVar3 != 0) {
          _DAT_00002163 = 0x2e002e;
          _DAT_00002167 = 0x2e;
          _DAT_0000216f = 0;
          _DAT_00002177 = 0;
          _DAT_0000217f = 0;
        }
        lVar3 = FUN_00001700(&uStack_77,(short *)&DAT_00002181);
        if (lVar3 != 0) {
          _DAT_00002181 = 0x2e0030;
          _DAT_00002185 = 0x2e0030;
          _DAT_00002189 = 0x2e0030;
          _DAT_0000218d = 0x30;
          _DAT_00002195 = 0;
          _DAT_0000219d = 0;
        }
        lVar3 = FUN_0000185c((undefined4 *)auStack_73,0x219f);
        bVar6 = local_80;
        if (lVar3 != 0) {
          _DAT_0000219f = 0x300030;
          _DAT_000021a3 = 0x30002d;
          _DAT_000021a7 = 0x2d0030;
          _DAT_000021ab = 0x300030;
          _DAT_000021af = 0x30002d;
          _DAT_000021b3 = 0x2d0030;
          _DAT_000021b7 = 0x300030;
          _DAT_000021bb = 0x30002d;
          _DAT_000021bf = 0x30;
        }
      }
      pwVar4 = u_ServerSetup_00002030;
      lVar3 = (**(code **)(DAT_00002090 + 0x58))
                        (u_ServerSetup_00002030,&DAT_00002020,local_res18[0],0x401,&DAT_000020a0);
      if (-1 < lVar3) {
        cVar2 = (char)local_res8;
        if (cVar2 != '\0') {
          if (bVar1 != 0) {
            pwVar4 = (wchar_t *)CONCAT71((int7)((ulonglong)pwVar4 >> 8),cVar2);
            FUN_00001280((ulonglong)pwVar4,bVar1);
            cVar2 = (char)local_res8;
          }
          if (bVar1 == 1) {
            local_68 = CONCAT71(auStack_97._0_7_,1);
            local_58 = auStack_8b._3_2_;
            local_56 = local_86;
            pwVar4 = (wchar_t *)(ulonglong)CONCAT11(SUB21(auStack_8b._3_2_,1),cVar2);
            uStack_60 = stack0xffffffffffffff70;
            FUN_0000108c((undefined8 *)pwVar4,(longlong)&local_68);
          }
        }
        puVar5 = (undefined8 *)CONCAT71((int7)((ulonglong)pwVar4 >> 8),local_res8._1_1_);
        if (local_res8._1_1_ != '\0') {
          if (bVar6 != 0) {
            FUN_00001280((ulonglong)puVar5,bVar6);
            puVar5 = (undefined8 *)CONCAT71((int7)((ulonglong)puVar5 >> 8),local_res8._1_1_);
          }
          if (bVar6 == 1) {
            local_68 = CONCAT71(auStack_7f._0_7_,local_80);
            local_58 = auStack_73._3_2_;
            local_56 = local_6e;
            uStack_60 = stack0xffffffffffffff88;
            FUN_0000108c(puVar5,(longlong)&local_68);
          }
        }
        lVar3 = 0;
      }
    }
  }
  return lVar3;
}

