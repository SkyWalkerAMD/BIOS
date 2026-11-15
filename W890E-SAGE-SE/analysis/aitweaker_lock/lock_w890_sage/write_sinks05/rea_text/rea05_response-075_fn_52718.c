
longlong WS05_52718(undefined8 param_1,byte *param_2)

{
  undefined8 uVar1;
  longlong lVar2;
  byte *pbVar3;
  byte *pbVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  undefined8 local_res8 [2];
  undefined1 local_res18 [8];
  undefined1 local_res20 [8];
  longlong local_58;
  longlong local_50;
  ulonglong local_48;
  byte *local_40;
  undefined8 local_38;
  undefined1 local_30 [8];
  
  uVar1 = DAT_000afc40;
  local_50 = 0;
  local_40 = (byte *)0x0;
  pbVar4 = (byte *)0x0;
  local_58 = 0;
  local_res8[0] = param_1;
  lVar2 = (**(code **)(DAT_000afc48 + 0x138))(2,&DAT_00093408,0,&local_48,&local_58);
  if (-1 < lVar2) {
    uVar6 = 0;
    if (local_48 != 0) {
      do {
        lVar2 = (**(code **)(DAT_000afc48 + 0x118))
                          (*(undefined8 *)(local_58 + uVar6 * 8),&DAT_00093408,&local_50,uVar1,0,1);
        if (-1 < lVar2) {
          lVar2 = (**(code **)(local_50 + 0x10))
                            (local_50,param_2,0,local_30,local_res8,local_res20,local_res18);
          if (-1 < lVar2) {
            uVar5 = *(undefined8 *)(local_58 + uVar6 * 8);
            lVar2 = (**(code **)(DAT_000afc48 + 0x118))(uVar5,&DAT_000933d8,&local_40,uVar1,0,1);
            if (-1 < lVar2) {
              pbVar3 = (byte *)FUN_0005a110(uVar5);
              if (pbVar3 + 4 != param_2) {
                FUN_00001580((undefined8 *)(pbVar3 + 4),(undefined8 *)param_2,0x10);
              }
              pbVar4 = FUN_00059fc4(local_40,pbVar3);
              (**(code **)(DAT_000afc48 + 0x48))(pbVar3);
              break;
            }
          }
        }
        uVar6 = uVar6 + 1;
      } while (uVar6 < local_48);
    }
    (**(code **)(DAT_000afc48 + 0x48))(local_58);
    if (pbVar4 == (byte *)0x0) {
      lVar2 = -0x7ffffffffffffff2;
    }
    else {
      lVar2 = (**(code **)(DAT_000afc48 + 200))(0,uVar1,pbVar4,0,0,&local_38);
      if (-1 < lVar2) {
        lVar2 = (**(code **)(DAT_000afc48 + 0xd0))(local_38,0,0);
      }
      (**(code **)(DAT_000afc48 + 0x48))(pbVar4);
    }
  }
  return lVar2;
}

