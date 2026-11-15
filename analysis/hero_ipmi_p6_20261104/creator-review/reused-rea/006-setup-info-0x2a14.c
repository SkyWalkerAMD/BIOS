
void FUN_00002a14(undefined8 param_1,short param_2)

{
  uint uVar1;
  longlong lVar2;
  longlong lVar3;
  char *pcVar4;
  byte *pbVar5;
  char *pcVar6;
  char cVar7;
  undefined2 uVar8;
  byte bVar9;
  byte bVar10;
  uint **ppuVar11;
  undefined1 uVar12;
  undefined8 *puVar13;
  ulonglong uVar14;
  short sVar15;
  uint *local_res18;
  undefined8 local_res20;
  undefined4 local_2b8;
  undefined4 local_2b4;
  undefined4 local_2b0;
  undefined4 local_2ac;
  undefined4 local_2a8;
  undefined4 local_2a4;
  undefined4 local_2a0;
  undefined1 local_298 [35];
  undefined2 local_275;
  
  local_res18 = (uint *)0x0;
  local_2b8 = 0x7a0079;
  local_2b4 = 0x7c007b;
  local_2b0 = 0x7e007d;
  local_2ac = 0x80007f;
  local_2a8 = 0x820081;
  local_2a4 = 0x840083;
  local_2a0 = 0x860085;
  if (param_2 == 0x14) {
    local_res20 = 0x267;
    lVar2 = (**(code **)(DAT_00015460 + 0x48))
                      (u_ServerSetup_0000d2c0,&DAT_0000a390,0,&local_res20,local_298);
    if (lVar2 < 0) {
      local_275 = 0x101;
    }
    puVar13 = &local_res20;
    local_res20 = 0xa1;
    lVar2 = (**(code **)(DAT_00015460 + 0x48))
                      (u_BstLogVar_0000d380,&DAT_0000a390,0,puVar13,&DAT_00015520);
    uVar12 = SUB81(puVar13,0);
    cVar7 = (char)local_275;
    if (lVar2 < 0) {
      cVar7 = '\x01';
    }
    local_275 = CONCAT11(local_275._1_1_,cVar7);
    if ((cVar7 == '\x01') || ((DAT_00015520 == 0x14 && (local_275._1_1_ == '\x01')))) {
      FUN_000002c0((undefined8 *)&DAT_00015520,0xa1);
    }
    bVar9 = DAT_00015520;
    ppuVar11 = &local_res18;
    lVar2 = (**(code **)(DAT_00015458 + 0x140))(&DAT_0000a3d0,0);
    if ((lVar2 < 0) || (uVar8 = 0x87, local_res18[0x1b] != 0)) {
      uVar8 = 0x88;
    }
    lVar3 = FUN_000097d0(param_1,uVar8,(ulonglong)ppuVar11,uVar12);
    if (lVar3 != 0) {
      FUN_0000968c(param_1,0x14,lVar3);
      (**(code **)(DAT_00015458 + 0x48))(lVar3);
    }
    if (lVar2 < 0) {
      if (bVar9 < 0x14) {
        (&DAT_00015521)[bVar9] = 0;
        FUN_000029b4(bVar9);
        bVar9 = bVar9 + 1;
      }
    }
    else {
      if (((char)local_res18[0x16] != '\0') &&
         (pcVar4 = (char *)FUN_000073b8(100), pcVar4 != (char *)0x0)) {
        FUN_000063f0(pcVar4,100,&DAT_0000d394,(ulonglong)*(byte *)((longlong)local_res18 + 0x5a));
        FUN_0000968c(param_1,0x1b,pcVar4);
        FUN_000063f0(pcVar4,100,&DAT_0000d39c,(ulonglong)*(byte *)((longlong)local_res18 + 0x5b));
        FUN_0000968c(param_1,0x1d,pcVar4);
        FUN_000063f0(pcVar4,100,(byte *)u__d__02x__02d_0000d3a8,
                     (ulonglong)((byte)local_res18[0x17] & 0x7f));
        FUN_0000968c(param_1,0x1f,pcVar4);
        FUN_000063f0(pcVar4,100,(byte *)u__x__x_0000d3c8,
                     (ulonglong)(*(byte *)((longlong)local_res18 + 0x5e) & 0xf));
        FUN_0000968c(param_1,0x21,pcVar4);
        (**(code **)(DAT_00015458 + 0x48))(pcVar4);
      }
      if (((*local_res18 != 0) && (bVar9 < 0x14)) && (uVar14 = 0, *local_res18 != 0)) {
        do {
          if (bVar9 == 0x14) break;
          uVar1 = local_res18[uVar14 + 1];
          if (uVar1 < 0x21007) {
            if (uVar1 == 0x21006) {
              uVar12 = 8;
            }
            else if (uVar1 == 0x21000) {
              uVar12 = 2;
            }
            else if (uVar1 == 0x21001) {
              uVar12 = 3;
            }
            else if (uVar1 == 0x21002) {
              uVar12 = 4;
            }
            else if (uVar1 == 0x21003) {
              uVar12 = 5;
            }
            else if (uVar1 == 0x21004) {
              uVar12 = 6;
            }
            else {
              if (uVar1 != 0x21005) goto LAB_00002d57;
              uVar12 = 7;
            }
          }
          else if (uVar1 == 0x21007) {
            uVar12 = 9;
          }
          else if (uVar1 == 0x21008) {
            uVar12 = 10;
          }
          else if (uVar1 == 0x21009) {
            uVar12 = 0xb;
          }
          else if (uVar1 == 0x2100a) {
            uVar12 = 0xc;
          }
          else if (uVar1 == 0x2100b) {
            uVar12 = 0xd;
          }
          else {
LAB_00002d57:
            uVar12 = 0;
          }
          (&DAT_00015521)[bVar9] = uVar12;
          FUN_000029b4(bVar9);
          bVar10 = (char)uVar14 + 1;
          uVar14 = (ulonglong)bVar10;
          bVar9 = bVar9 + 1;
        } while ((uint)bVar10 < *local_res18);
      }
    }
    uVar14 = 0xa1;
    pcVar4 = (char *)((longlong)&IMAGE_DOS_HEADER_00000000.e_cblp + 1);
    DAT_00015520 = bVar9;
    (**(code **)(DAT_00015460 + 0x58))(u_BstLogVar_0000d380,&DAT_0000a390,3,0xa1,&DAT_00015520);
    pbVar5 = (byte *)FUN_000097d0(param_1,0x89,(ulonglong)pcVar4,(char)uVar14);
    if (pbVar5 != (byte *)0x0) {
      pcVar6 = (char *)FUN_000073b8(100);
      if (pcVar6 != (char *)0x0) {
        uVar14 = (ulonglong)DAT_00015520;
        FUN_000063f0(pcVar6,100,pbVar5,uVar14);
        pcVar4 = pcVar6;
        FUN_0000968c(param_1,99,pcVar6);
        (**(code **)(DAT_00015458 + 0x48))(pcVar6);
      }
      (**(code **)(DAT_00015458 + 0x48))(pbVar5);
    }
    sVar15 = 100;
    if (DAT_00015520 == 0) {
      lVar2 = FUN_000097d0(param_1,0x7a,(ulonglong)pcVar4,(char)uVar14);
      if (lVar2 != 0) {
        FUN_0000968c(param_1,100,lVar2);
        (**(code **)(DAT_00015458 + 0x48))(lVar2);
      }
    }
    else {
      pcVar6 = (char *)FUN_000097d0(param_1,0x8a,(ulonglong)pcVar4,(char)uVar14);
      if (pcVar6 != (char *)0x0) {
        pcVar4 = pcVar6;
        FUN_0000968c(param_1,0x78,pcVar6);
        (**(code **)(DAT_00015458 + 0x48))(pcVar6);
      }
      bVar9 = 0;
      if (DAT_00015520 != 0) {
        do {
          lVar2 = FUN_000097d0(param_1,*(undefined2 *)
                                        ((longlong)&local_2b8 +
                                        (ulonglong)(byte)(&DAT_00015521)[bVar9] * 2),
                               (ulonglong)pcVar4,(char)uVar14);
          if (lVar2 != 0) {
            pcVar6 = (char *)FUN_000073b8(100);
            if (pcVar6 != (char *)0x0) {
              uVar14 = (ulonglong)(byte)(&DAT_00015537)[(ulonglong)bVar9 * 4];
              FUN_000063f0(pcVar6,100,(byte *)u__02d__02d__02d__02d__02d__02d__s_0000d3e0,uVar14);
              pcVar4 = pcVar6;
              FUN_0000968c(param_1,sVar15,pcVar6);
              (**(code **)(DAT_00015458 + 0x48))(pcVar6);
            }
            (**(code **)(DAT_00015458 + 0x48))(lVar2);
          }
          bVar9 = bVar9 + 1;
          sVar15 = sVar15 + 1;
        } while (bVar9 < DAT_00015520);
      }
    }
  }
  return;
}

