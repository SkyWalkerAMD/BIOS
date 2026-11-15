
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_000004e0(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  longlong lVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  undefined7 uVar6;
  byte local_res8;
  undefined7 uStackX_9;
  undefined8 local_res10;
  undefined1 local_res18 [8];
  byte local_res20 [8];
  undefined4 local_78 [2];
  undefined8 local_70;
  byte local_68;
  undefined1 auStack_67 [8];
  undefined4 uStack_5f;
  byte abStack_5b [3];
  undefined2 local_58;
  undefined1 local_56;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined2 local_38;
  undefined1 local_36;
  
  uStackX_9 = (undefined7)((ulonglong)param_1 >> 8);
  _local_res8 = CONCAT71(uStackX_9,1);
  local_res10 = param_2;
  lVar2 = (**(code **)(DAT_00000d08 + 0x140))(0xc90,0,0xf88);
  if (-1 < lVar2) {
    if (DAT_00000f88 == (undefined8 *)0x0) {
      lVar2 = -0x7ffffffffffffffe;
    }
    else {
      lVar2 = FUN_00000af8((longlong)DAT_00000f88,(char *)&local_res10,&local_res8);
      if (-1 < lVar2) {
        local_70 = 0x267;
        lVar2 = (**(code **)(DAT_00000d10 + 0x48))(0xcb0,0xca0,local_78,&local_70,0xd20);
        local_68 = DAT_00000d46;
        if (lVar2 < 0) {
          local_68 = 0;
        }
        if ((byte)local_res10 != '\0') {
          DAT_00000d46 = 0;
          lVar2 = FUN_000007c0((undefined4 *)auStack_67,(short *)&DAT_00000d47);
          if (lVar2 != 0) {
            _DAT_00000d47 = 0x2e002e;
            _DAT_00000d4b = 0x2e002e;
            _DAT_00000d53 = 0;
            _DAT_00000d5b = 0;
            _DAT_00000d63 = 0;
          }
          lVar2 = FUN_000007c0((undefined4 *)(auStack_67 + 4),(short *)&DAT_00000d65);
          if (lVar2 != 0) {
            _DAT_00000d65 = 0x2e002e;
            _DAT_00000d69 = 0x2e002e;
            _DAT_00000d71 = 0;
            _DAT_00000d79 = 0;
            _DAT_00000d81 = 0;
          }
          lVar2 = FUN_000007c0(&uStack_5f,(short *)&DAT_00000d83);
          if (lVar2 != 0) {
            _DAT_00000d83 = 0x2e0030;
            _DAT_00000d87 = 0x2e0030;
            _DAT_00000d8b = 0x2e0030;
            _DAT_00000d8f = 0x30;
            _DAT_00000d97 = 0;
            _DAT_00000d9f = 0;
          }
          lVar2 = FUN_00000924(abStack_5b,0xda1);
          if (lVar2 != 0) {
            _DAT_00000da1 = 0x300030;
            _DAT_00000da5 = 0x30002d;
            _DAT_00000da9 = 0x2d0030;
            _DAT_00000dad = 0x300030;
            _DAT_00000db1 = 0x30002d;
            _DAT_00000db5 = 0x2d0030;
            _DAT_00000db9 = 0x300030;
            _DAT_00000dbd = 0x30002d;
            _DAT_00000dc1 = 0x30;
          }
        }
        bVar1 = local_68;
        uVar5 = 0xca0;
        uVar3 = 0xcb0;
        lVar2 = (**(code **)(DAT_00000d10 + 0x58))(0xcb0,0xca0,local_78[0],0x267,0xd20);
        if (-1 < lVar2) {
          puVar4 = (undefined8 *)CONCAT71((int7)((ulonglong)uVar3 >> 8),(byte)local_res10);
          if ((byte)local_res10 != 0) {
            if (bVar1 != 0) {
              local_res20[1] = 4;
              local_res20[0] = (byte)local_res10 & 0xf;
              uVar6 = (undefined7)((ulonglong)uVar5 >> 8);
              local_res20[2] = bVar1 & 0xf;
              lVar2 = FUN_00000a5c((ulonglong)puVar4,(byte)local_res10);
              if (-1 < lVar2) {
                _local_res8 = CONCAT71(uStackX_9,1);
                puVar4 = DAT_00000f88;
                (*(code *)DAT_00000f88[1])
                          (DAT_00000f88,CONCAT71(uVar6,0xc),0,1,local_res20,3,local_res18,
                           &local_res8);
              }
              puVar4 = (undefined8 *)CONCAT71((int7)((ulonglong)puVar4 >> 8),(byte)local_res10);
            }
            if (bVar1 == 1) {
              local_48 = CONCAT71(auStack_67._0_7_,local_68);
              local_38 = local_58;
              local_36 = local_56;
              uStack_40 = stack0xffffffffffffffa0;
              FUN_000002ec(puVar4,(longlong)&local_48);
            }
          }
          lVar2 = 0;
        }
      }
    }
  }
  return lVar2;
}

