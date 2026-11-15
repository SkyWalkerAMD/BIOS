
longlong FUN_00001174(undefined8 param_1,undefined8 param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  longlong lVar5;
  undefined8 uVar6;
  byte local_res8;
  undefined7 uStackX_9;
  undefined8 local_res10;
  byte local_res18 [8];
  undefined8 local_res20;
  undefined1 local_28 [3];
  byte local_25;
  char local_23;
  byte local_22;
  
  uVar6 = 0;
  _local_res8 = CONCAT71((int7)((ulonglong)param_1 >> 8),1);
  lVar5 = 0x2000;
  local_res10 = param_2;
  lVar2 = (**(code **)(DAT_00002058 + 0x140))(0x2000,0,&DAT_00002040);
  lVar1 = DAT_00002040;
  if (-1 < lVar2) {
    if (DAT_00002040 == 0) {
      lVar2 = -0x7ffffffffffffffe;
    }
    else {
      local_res10 = CONCAT71(local_res10._1_7_,0x10);
      uVar6 = CONCAT71((int7)((ulonglong)uVar6 >> 8),6);
      lVar5 = DAT_00002040;
      lVar2 = (**(code **)(DAT_00002040 + 8))(DAT_00002040,uVar6,0,1,0,0,local_28,&local_res10);
      if ((-1 < lVar2) && (0x7f < local_25)) {
        *(undefined4 *)(lVar1 + -4) = 3;
      }
    }
    if (-1 < lVar2) {
      if (((local_22 & 4) == 0) || ((local_23 != 'Q' && (local_23 != '\x02')))) {
        lVar2 = -0x7ffffffffffffffd;
      }
      else {
        puVar3 = (undefined8 *)FUN_00001800(lVar5,uVar6);
        puVar4 = (undefined8 *)0x0;
        if (puVar3 != (undefined8 *)0x0) {
          puVar4 = FUN_00001070(puVar3,0x98);
        }
        DAT_00002048 = puVar4;
        if (puVar4 == (undefined8 *)0x0) {
          lVar2 = -0x7ffffffffffffff7;
        }
        else {
          *puVar4 = 0x464f4c45;
          *(undefined4 *)(puVar4 + 1) = 1;
          puVar4[0x12] = FUN_000016d8;
          puVar4[0x11] = &LAB_00001538;
          puVar4[0x10] = &LAB_00001430;
          puVar4[0xf] = &LAB_00001320;
          local_res20 = 0;
          lVar2 = (**(code **)(DAT_00002058 + 0x80))(&local_res20,&DAT_00002010,0);
          if (lVar2 < 0) {
            (**(code **)(DAT_00002058 + 0x48))();
          }
          else {
            FUN_000016d8((longlong)(DAT_00002048 + 0xf),1,&local_res8,local_res18);
            lVar2 = 0;
          }
        }
      }
    }
  }
  return lVar2;
}

