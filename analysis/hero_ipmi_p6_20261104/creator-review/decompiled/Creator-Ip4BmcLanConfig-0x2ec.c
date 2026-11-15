
void FUN_000002ec(undefined8 *param_1,longlong param_2)

{
  byte bVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined7 uVar5;
  undefined8 *puVar4;
  byte bVar6;
  undefined1 local_res8 [8];
  undefined1 local_res10 [8];
  byte local_res18 [2];
  undefined8 local_res1a;
  byte local_38 [2];
  undefined8 local_36;
  
  bVar1 = (byte)param_1;
  local_res18[1] = 3;
  bVar6 = bVar1 & 0xf;
  puVar3 = (undefined8 *)(param_2 + 1);
  local_res18[0] = bVar6;
  if (&local_res1a != puVar3) {
    param_1 = &local_res1a;
    FUN_00000260(param_1,puVar3,4);
  }
  uVar5 = (undefined7)((ulonglong)puVar3 >> 8);
  lVar2 = FUN_00000a5c((ulonglong)param_1,bVar1);
  if (-1 < lVar2) {
    local_res8[0] = 1;
    puVar3 = DAT_00000f88;
    lVar2 = (*(code *)DAT_00000f88[1])
                      (DAT_00000f88,CONCAT71(uVar5,0xc),0,1,local_res18,6,local_res10,local_res8);
    if (-1 < lVar2) {
      puVar4 = (undefined8 *)(param_2 + 5);
      local_res1a._7_1_ = 6;
      local_res1a._6_1_ = bVar6;
      if ((undefined8 *)&stack0x00000022 != puVar4) {
        puVar3 = (undefined8 *)&stack0x00000022;
        FUN_00000260(puVar3,puVar4,4);
      }
      uVar5 = (undefined7)((ulonglong)puVar4 >> 8);
      lVar2 = FUN_00000a5c((ulonglong)puVar3,bVar1);
      if (-1 < lVar2) {
        local_res10[0] = 0;
        local_res8[0] = 1;
        puVar3 = DAT_00000f88;
        lVar2 = (*(code *)DAT_00000f88[1])
                          (DAT_00000f88,CONCAT71(uVar5,0xc),0,1,(longlong)&local_res1a + 6,6,
                           local_res10,local_res8);
        if (-1 < lVar2) {
          puVar4 = (undefined8 *)(param_2 + 9);
          local_res18[1] = 0xc;
          local_res18[0] = bVar6;
          if (&local_res1a != puVar4) {
            puVar3 = &local_res1a;
            FUN_00000260(puVar3,puVar4,4);
          }
          uVar5 = (undefined7)((ulonglong)puVar4 >> 8);
          lVar2 = FUN_00000a5c((ulonglong)puVar3,bVar1);
          if (-1 < lVar2) {
            local_res10[0] = 0;
            local_res8[0] = 1;
            puVar3 = DAT_00000f88;
            lVar2 = (*(code *)DAT_00000f88[1])
                              (DAT_00000f88,CONCAT71(uVar5,0xc),0,1,local_res18,6,local_res10,
                               local_res8);
            if (-1 < lVar2) {
              puVar4 = (undefined8 *)(param_2 + 0xd);
              local_38[1] = 0xd;
              local_38[0] = bVar6;
              if (&local_36 != puVar4) {
                puVar3 = &local_36;
                FUN_00000260(puVar3,puVar4,6);
              }
              uVar5 = (undefined7)((ulonglong)puVar4 >> 8);
              lVar2 = FUN_00000a5c((ulonglong)puVar3,bVar1);
              if (-1 < lVar2) {
                local_res10[0] = 0;
                local_res8[0] = 1;
                (*(code *)DAT_00000f88[1])
                          (DAT_00000f88,CONCAT71(uVar5,0xc),0,1,local_38,8,local_res10,local_res8);
              }
            }
          }
        }
      }
    }
  }
  return;
}

