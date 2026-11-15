/* {"status": "resolved", "address": "0xa3c", "name": "FUN_00000a3c"} */

ulonglong FUN_00000a3c(longlong param_1,longlong ******param_2)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined8 *puVar4;
  longlong ***********ppppppppppplVar5;
  longlong *******ppppppplVar6;
  undefined8 uVar7;
  longlong **********local_res8;
  longlong **********local_res10;
  longlong ******local_res20;
  char *local_58;
  undefined8 local_50;
  undefined1 local_40 [2];
  undefined1 local_3e;
  
  local_res10 = (longlong **********)param_2;
  local_res20 = param_2;
  uVar2 = (**(code **)(DAT_000023d0 + 0x118))
                    (param_2,&DAT_000022a0,&local_res8,*(undefined8 *)(param_1 + 0x28),param_2,0x10)
  ;
  if ((longlong)uVar2 < 0) {
    return uVar2;
  }
  uVar2 = (**(code **)(DAT_000023d0 + 0x118))
                    (local_res10,&DAT_00002290,&local_58,*(undefined8 *)(param_1 + 0x28),local_res10
                     ,0x10);
  uVar7 = *(undefined8 *)(param_1 + 0x28);
  if ((longlong)uVar2 < 0) {
LAB_00000ad5:
    (**(code **)(DAT_000023d0 + 0x120))(local_res10,&DAT_000022a0,uVar7,local_res10);
  }
  else {
    (**(code **)(DAT_000023d0 + 0x120))(local_res10,&DAT_00002290,uVar7,local_res10);
    ppppppplVar6 = (longlong *******)&local_50;
    ppppppppppplVar5 = (longlong ***********)local_res8;
    lVar3 = (*(code *)local_res8[8])();
    if ((((-1 < lVar3) && (local_50._5_1_ == '\n')) && (local_50._6_1_ == '\0')) &&
       (local_50._7_1_ == '\0')) {
      uVar2 = FUN_000005fc(local_58,&local_50);
      if (-1 < (longlong)uVar2) {
        lVar3 = CONCAT17(local_50._7_1_,
                         CONCAT16(local_50._6_1_,CONCAT15(local_50._5_1_,(undefined5)local_50)));
        *(longlong ***********)(lVar3 + 0x110) = local_res10;
        *(longlong ***********)(lVar3 + 0x128) = local_res8;
        FUN_00001118(local_res8,lVar3);
        return uVar2;
      }
      ppppppplVar6 = (longlong *******)&DAT_00002290;
      ppppppppppplVar5 = (longlong ***********)local_res10;
      uVar2 = (**(code **)(DAT_000023d0 + 0x98))(local_res10,&DAT_00002290,&local_50);
      if (-1 < (longlong)uVar2) {
        ppppppplVar6 = &local_res20;
        ppppppppppplVar5 = &local_res8;
        uVar2 = FUN_00000820((longlong *)ppppppppppplVar5,ppppppplVar6,&local_50);
        param_2 = local_res20;
      }
      if ((longlong)uVar2 < 0) {
        uVar7 = *(undefined8 *)(param_1 + 0x28);
        goto LAB_00000ad5;
      }
    }
    puVar4 = (undefined8 *)FUN_00001f94(ppppppppppplVar5,ppppppplVar6);
    if ((puVar4 == (undefined8 *)0x0) ||
       (puVar4 = FUN_00000300(puVar4,0x180), puVar4 == (undefined8 *)0x0)) {
      (**(code **)(DAT_000023d0 + 0x120))
                (local_res10,&DAT_000022a0,*(undefined8 *)(param_1 + 0x28),local_res10);
      uVar2 = 0x8000000000000009;
    }
    else {
      FUN_00000fc8(local_res8,puVar4 + 0x26);
      (*(code *)local_res8[8])(local_res8,local_40);
      *(undefined4 *)puVar4 = 0x73646e72;
      *(undefined1 *)(puVar4 + 0x27) = local_3e;
      puVar4[0x23] = param_2;
      puVar4[0x22] = 0;
      puVar4[0x24] = local_res8;
      puVar4[0x15] = &LAB_000019f8;
      puVar4[0x16] = FUN_000018f0;
      puVar4[0x17] = FUN_00001210;
      puVar4[0x18] = FUN_00001298;
      puVar4[0x19] = FUN_00001344;
      puVar4[0x1a] = &LAB_00001374;
      puVar4[0x1b] = &LAB_00001398;
      puVar4[0x1c] = &LAB_000013bc;
      puVar4[0x1d] = FUN_000013e0;
      puVar4[0x1e] = FUN_00001490;
      puVar4[0x1f] = FUN_000014ec;
      puVar4[0x20] = &LAB_000016bc;
      puVar4[0x21] = &LAB_000016bc;
      puVar4[1] = &LAB_000016bc;
      puVar4[2] = &LAB_000016c0;
      puVar4[3] = &LAB_000016bc;
      puVar4[4] = &LAB_00001718;
      puVar4[5] = &LAB_000016bc;
      puVar4[6] = FUN_0000173c;
      puVar4[7] = FUN_00001810;
      puVar4[8] = FUN_00001898;
      puVar4[9] = &LAB_000016bc;
      puVar4[10] = &LAB_00001544;
      puVar4[0xb] = &LAB_000016bc;
      puVar4[0xc] = 0;
      puVar4[0xd] = &LAB_000016bc;
      puVar4[0xe] = &LAB_000016bc;
      puVar4[0xf] = &LAB_000018e4;
      puVar1 = puVar4 + 0x2e;
      puVar4[0x10] = &LAB_000016bc;
      puVar4[0x11] = 0;
      puVar4[0x12] = 0;
      *(undefined4 *)(puVar4 + 0x2d) = 0x4000;
      *(undefined4 *)((longlong)puVar4 + 0x164) = 1;
      *(undefined4 *)((longlong)puVar4 + 0x16c) = 0;
      *puVar1 = puVar1;
      puVar4[0x2f] = puVar1;
      FUN_000006e8((longlong)puVar4);
      if (puVar4[0x25] == 0) {
        uVar2 = 0;
      }
      else {
        uVar2 = (**(code **)(DAT_000023d0 + 0x80))(&local_res10,&DAT_000022d0,0,puVar4 + 1);
        if (-1 < (longlong)uVar2) {
          FUN_00001118((undefined8 *)puVar4[0x24],(longlong)puVar4);
          return 0;
        }
        (**(code **)(DAT_000023d0 + 0x120))
                  (local_res10,&DAT_000022a0,*(undefined8 *)(param_1 + 0x28),local_res10);
      }
      (**(code **)(DAT_000023d0 + 0x48))(puVar4[0x26]);
      (**(code **)(DAT_000023d0 + 0x48))(puVar4);
    }
  }
  return uVar2;
}

