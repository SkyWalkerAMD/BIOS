/* {"status": "resolved", "address": "0x3d0", "name": "FUN_000003d0"} */

void FUN_000003d0(undefined8 param_1,longlong param_2)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  ulonglong uVar4;
  
  DAT_00002b90 = *(undefined8 *)(param_2 + 0x60);
  DAT_00002b88 = param_2;
  FUN_00002770();
  psVar3 = (short *)FUN_00002770();
  do {
    if (*psVar3 == -1) {
      psVar3 = (short *)0x0;
LAB_00000424:
      if (psVar3 == (short *)0x0) {
        uVar4 = FUN_00000360();
        FUN_00000350();
        uVar1 = in(0x1808);
        FUN_00000330();
        while (iVar2 = in(0x1808), (((uVar1 & 0xffffff) + 0x16b) - iVar2 >> 0x17 & 1) == 0) {
          FUN_00000320();
        }
        FUN_00000330();
        if ((uVar4 >> 9 & 1) == 0) {
          FUN_00000350();
        }
        else {
          FUN_00000340();
        }
        return;
      }
      if ((DAT_00002a78 == *(longlong *)(psVar3 + 4)) && (DAT_00002a80 == *(longlong *)(psVar3 + 8))
         ) {
        return;
      }
    }
    else if (*psVar3 == 4) goto LAB_00000424;
    psVar3 = (short *)((longlong)psVar3 + (ulonglong)(ushort)psVar3[1]);
  } while( true );
}



/* {"status": "resolved", "address": "0x5a0", "name": "FUN_000005a0"} */

longlong FUN_000005a0(longlong param_1,undefined8 param_2)

{
  longlong lVar1;
  undefined1 local_res8 [8];
  
  lVar1 = (**(code **)(DAT_00002b90 + 0x118))
                    (param_2,&DAT_00002a50,local_res8,*(undefined8 *)(param_1 + 0x28),param_2,0x10);
  if (-1 < lVar1) {
    (**(code **)(DAT_00002b90 + 0x120))
              (param_2,&DAT_00002a50,*(undefined8 *)(param_1 + 0x28),param_2);
  }
  return lVar1;
}



/* {"status": "resolved", "address": "0x61c", "name": "FUN_0000061c"} */

longlong FUN_0000061c(longlong param_1,undefined8 param_2)

{
  longlong lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  char cVar6;
  longlong lVar7;
  undefined8 *puVar8;
  longlong local_res8;
  undefined2 local_res20 [4];
  undefined4 uVar9;
  char *local_68;
  undefined1 local_60 [9];
  undefined8 local_57;
  undefined8 local_4f;
  undefined4 local_47;
  undefined2 local_43;
  undefined1 local_41;
  
  local_60._1_8_ = 0;
  local_57 = 0;
  local_4f = 0;
  local_47 = 0;
  puVar5 = (undefined8 *)0x0;
  local_43 = 0;
  local_41 = 0;
  cVar6 = '\0';
  local_60[0] = 0;
  lVar1 = (**(code **)(DAT_00002b90 + 0x118))
                    (param_2,&DAT_00002a50,&local_res8,*(undefined8 *)(param_1 + 0x28),param_2,0x10)
  ;
  if (-1 < lVar1) {
    lVar1 = (**(code **)(DAT_00002b90 + 0x118))
                      (param_2,&DAT_000029e0,&local_68,*(undefined8 *)(param_1 + 0x28),param_2,0x10)
    ;
    if (lVar1 < 0) {
      (**(code **)(DAT_00002b90 + 0x120))
                (param_2,&DAT_00002a50,*(undefined8 *)(param_1 + 0x28),param_2);
    }
    else {
      (**(code **)(local_res8 + 0xb8))(local_res8,local_60);
      lVar7 = local_res8;
      lVar1 = (**(code **)(local_res8 + 0xc0))(local_res8,local_res20);
      if (-1 < lVar1) {
        puVar2 = (undefined8 *)FUN_00002740(lVar7,0x370);
        if ((puVar2 != (undefined8 *)0x0) &&
           (puVar3 = FUN_000002e0(puVar2,0x370), puVar3 != (undefined8 *)0x0)) {
          puVar8 = DAT_00002b80;
          puVar4 = puVar5;
          if (DAT_00002b80 == (undefined8 *)0x0) {
            puVar2 = (undefined8 *)FUN_00002740(puVar2,0x30);
            puVar4 = (undefined8 *)0x0;
            if (puVar2 != (undefined8 *)0x0) {
              puVar4 = FUN_000002e0(puVar2,0x30);
            }
            if (puVar4 == (undefined8 *)0x0) {
              (**(code **)(DAT_00002b90 + 0x48))(puVar3);
            }
            puVar8 = puVar4;
            if (((ulonglong)puVar4 & 0xf) != 0) {
              puVar8 = puVar4 + 1;
            }
            DAT_00002b80 = puVar8;
            *(undefined4 *)((longlong)puVar8 + 4) = 0x20020;
            puVar8[2] = &LAB_00002500;
            *(undefined4 *)puVar8 = 0x45585021;
            *(undefined2 *)((longlong)puVar8 + 9) = 1;
            *(undefined1 *)(puVar8 + 1) = 3;
            *(undefined1 *)((longlong)puVar8 + 0xb) = 0;
            *(undefined4 *)((longlong)puVar8 + 0xc) = 0x4000c1f0;
            *(undefined4 *)(puVar8 + 3) = 0x1000000;
            *(undefined4 *)((longlong)puVar8 + 0x1c) = 0x52425355;
            if (*(char *)((longlong)puVar8 + 4) != '\0') {
              cVar6 = '\0';
              do {
                cVar6 = cVar6 + *(char *)((longlong)puVar5 + (longlong)puVar8);
                puVar5 = (undefined8 *)((longlong)puVar5 + 1);
              } while (puVar5 < (undefined8 *)(ulonglong)*(byte *)((longlong)puVar8 + 4));
            }
            *(char *)((longlong)puVar8 + 5) = *(char *)((longlong)puVar8 + 5) - cVar6;
          }
          puVar3[2] = puVar8;
          puVar5 = puVar3 + 9;
          *(ushort *)((longlong)puVar3 + 0x2c) =
               CONCAT11(*(undefined1 *)((longlong)puVar8 + 10),*(undefined1 *)((longlong)puVar8 + 7)
                       );
          FUN_00002470((longlong)puVar5);
          *(undefined4 *)puVar5 = 0x6463696e;
          puVar3[10] = local_res8;
          *(undefined2 *)(puVar3 + 0x51) = local_res20[0];
          if ((undefined8 *)((longlong)puVar3 + 0x28a) != (undefined8 *)local_60) {
            FUN_000002a0((undefined8 *)((longlong)puVar3 + 0x28a),(undefined8 *)local_60,0x20);
          }
          *(undefined1 *)(puVar3 + 0x4e) = 0;
          puVar2 = puVar3 + 8;
          *(undefined8 **)(&DAT_00002ba0 + (ulonglong)*(ushort *)((longlong)puVar3 + 0x2c) * 8) =
               puVar3;
          lVar1 = FUN_00000498(puVar2,local_68,(longlong)puVar5);
          if ((lVar1 < 0) && (FUN_00002470(0), puVar4 != (undefined8 *)0x0)) {
            (**(code **)(DAT_00002b90 + 0x48))(puVar4);
          }
          *puVar3 = 0x69646e75;
          puVar5 = puVar3 + 6;
          puVar3[1] = 0x20000;
          *(undefined4 *)(puVar3 + 5) = 0x1010301;
          *(undefined4 *)(puVar3 + 4) = 0;
          puVar3[3] = 0;
          *(undefined4 *)((longlong)puVar3 + 0x24) = 0x49444e55;
          *puVar5 = 0;
          *(undefined2 *)((longlong)puVar3 + 0x366) = 0;
          (**(code **)(local_res8 + 0xb0))(local_res8,1,0x10,(longlong)puVar3 + 0x364);
          uVar9 = 0;
          lVar1 = (**(code **)(DAT_00002b90 + 0x148))
                            (puVar5,&DAT_000029d0,puVar3 + 1,&DAT_000029e0,*puVar2,0);
          if (lVar1 < 0) {
            *(undefined8 *)(&DAT_00002ba0 + (ulonglong)*(ushort *)((longlong)puVar3 + 0x2c) * 8) = 0
            ;
            (**(code **)(DAT_00002b90 + 0x48))(*puVar2);
          }
          lVar1 = (**(code **)(DAT_00002b90 + 0x118))
                            (param_2,&DAT_00002a50,&local_res8,*(undefined8 *)(param_1 + 0x28),
                             *puVar5,CONCAT44(uVar9,8));
          return lVar1;
        }
        lVar1 = -0x7ffffffffffffffd;
      }
      (**(code **)(DAT_00002b90 + 0x120))
                (param_2,&DAT_000029e0,*(undefined8 *)(param_1 + 0x28),param_2);
      (**(code **)(DAT_00002b90 + 0x120))
                (param_2,&DAT_00002a50,*(undefined8 *)(param_1 + 0x28),param_2);
    }
  }
  return lVar1;
}

