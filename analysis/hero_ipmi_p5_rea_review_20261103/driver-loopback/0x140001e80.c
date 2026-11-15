
/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulonglong FUN_140001e80(void)

{
  bool bVar1;
  ushort uVar2;
  short sVar3;
  int iVar4;
  undefined7 extraout_var;
  undefined7 extraout_var_00;
  longlong lVar5;
  undefined7 extraout_var_01;
  undefined8 uVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined7 extraout_var_02;
  undefined7 extraout_var_03;
  undefined7 extraout_var_04;
  undefined *puVar9;
  ushort uVar10;
  char *pcVar11;
  int iVar12;
  uint uVar13;
  ulonglong uVar14;
  ulonglong local_b8;
  longlong local_b0;
  longlong local_a8 [2];
  char *local_98;
  longlong local_90;
  longlong local_88 [2];
  undefined8 local_78;
  undefined1 local_68 [48];
  
  if (DAT_140057100 != '\0') {
    return 0x8000000000000014;
  }
  if (DAT_140057104 != 0) {
    return 0x800000000000000f;
  }
  DAT_140057100 = 1;
  local_a8[1] = 0;
  DAT_140057108 = 45000;
  DAT_14005710c = 200000;
  uVar13 = 0;
  do {
    pcVar11 = "Unavailable";
    if (0x17 < uVar13) {
      pcVar11 = "-";
    }
    FUN_140003420(uVar13,(longlong)pcVar11);
    uVar13 = uVar13 + 1;
  } while (uVar13 != 0x28);
  DAT_140078d68 = 0;
  FUN_140003b90("P1_READ_BEGIN\r\n");
  FUN_140004020();
  bVar1 = FUN_140003b20(&DAT_140078bf0,"ROG MAXIMUS Z790 HERO");
  if (((int)CONCAT71(extraout_var,bVar1) == 0) ||
     (bVar1 = FUN_140003b20(&DAT_140078c50,"3107"), (int)CONCAT71(extraout_var_00,bVar1) == 0)) {
    pcVar11 = "P1 hardware access requires ROG MAXIMUS Z790 HERO BIOS 3107.";
LAB_140002058:
    FUN_140003e50(pcVar11);
    uVar14 = 0x8000000000000007;
  }
  else {
    lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x140))
                      (&DAT_140057050,0,local_a8 + 1);
    if (lVar5 < 0) {
      pcVar11 = "PCI enumeration not ready.";
      goto LAB_140002058;
    }
    local_a8[1] = 0;
    lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x140))
                      (&DAT_140057060,0,local_a8 + 1);
    if (lVar5 != -0x7ffffffffffffff2) {
      pcVar11 = "An IPMI transport already owns the card; raw KCS is not used.";
      goto LAB_140002058;
    }
    local_b0 = 0;
    local_b8 = 0;
    lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x138))
                      (2,&DAT_140057070,0,&local_b8,&local_b0);
    if (local_b0 == 0 || lVar5 < 0) {
LAB_140002580:
      pcVar11 = "ASPEED PCI location/BAR or memory-enable verification failed.";
      goto LAB_140002058;
    }
    if (local_b8 - 0x1001 < 0xfffffffffffff000) {
      (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))();
      goto LAB_140002580;
    }
    uVar14 = 0;
    iVar12 = 0;
    do {
      local_a8[0] = 0;
      lVar5 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x98))
                        (*(undefined8 *)(local_b0 + uVar14 * 8),&DAT_140057070,local_a8);
      if (((local_a8[0] != 0 && -1 < lVar5) &&
          (lVar5 = (**(code **)(local_a8[0] + 0x30))(local_a8[0],0,0,0x40,&local_78), -1 < lVar5))
         && (iVar4 = FUN_140003e30((undefined4 *)&local_78), iVar4 == 0x24021a03)) {
        iVar12 = iVar12 + 1;
        DAT_140057178 = local_a8[0];
        FUN_140003970(0x140057180,(longlong)&local_78,0x40);
      }
      uVar14 = uVar14 + 1;
    } while (uVar14 < local_b8);
    (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))(local_b0);
    if ((iVar12 != 1) ||
       (bVar1 = FUN_140004eb0(&DAT_140057180), (int)CONCAT71(extraout_var_02,bVar1) == 0))
    goto LAB_140002580;
    local_78 = 0;
    local_a8[0] = 0;
    local_88[0] = 0;
    local_90 = 0;
    lVar5 = (**(code **)(DAT_140057178 + 0x70))(DAT_140057178,&local_78,local_a8,local_88,&local_90)
    ;
    if ((((lVar5 < 0) || ((local_78 != 0 || (local_a8[0] != 4)))) || (local_88[0] != 1)) ||
       (local_90 != 0)) goto LAB_140002580;
    local_98 = (char *)0x0;
    local_88[1] = 0;
    bVar1 = true;
    lVar5 = (**(code **)(DAT_140057178 + 0x80))(DAT_140057178,1,local_88 + 1,&local_98);
    pcVar11 = local_98;
    if ((((local_98 != (char *)0x0 && -1 < lVar5) && (bVar1 = true, *local_98 == -0x76)) &&
        (sVar3 = FUN_140003e20((undefined2 *)(local_98 + 1)), sVar3 == 0x2b)) &&
       (pcVar11[3] == '\0')) {
      uVar14 = FUN_140003e40((undefined8 *)(pcVar11 + 0xe));
      uVar13 = FUN_140003e30((undefined4 *)&DAT_140057194);
      if (uVar14 == (uVar13 & 0xfffffff0)) {
        uVar14 = FUN_140003e40((undefined8 *)(pcVar11 + 0x26));
        bVar1 = uVar14 < 0xe8d;
      }
    }
    if (local_98 != (char *)0x0) {
      (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x48))();
    }
    FUN_140003b90("PCI_CONFIG ");
    puVar9 = &DAT_140057180;
    FUN_140003d10(0x140057180,0x40);
    if ((bVar1) || (bVar1 = FUN_140002590(), (int)CONCAT71(extraout_var_03,bVar1) == 0))
    goto LAB_140002580;
    _DAT_140057110 = 0;
    _DAT_140057118 = FUN_1400026d0;
    _DAT_140057120 = &LAB_1400027b0;
    _DAT_140057128 = &LAB_140002890;
    _DAT_140057130 = 0;
    uRam0000000140057138 = 0;
    _DAT_140057140 = 0;
    uRam0000000140057148 = 0;
    _DAT_140057150 = 0;
    uRam0000000140057158 = 0;
    _DAT_140057160 = 0;
    uRam0000000140057168 = 0;
    _DAT_140057170 = 0;
    uVar6 = FUN_1400028d0(puVar9);
    uVar14 = 0x8000000000000007;
    if ((int)uVar6 != 0) {
      uVar6 = FUN_140002a00();
      uVar14 = 0x8000000000000007;
      if ((int)uVar6 != 0) {
        bVar1 = FUN_140002c90();
        uVar14 = 0x8000000000000007;
        if ((int)CONCAT71(extraout_var_04,bVar1) != 0) {
          uVar6 = FUN_140002fb0();
          uVar14 = 0x8000000000000007;
          if ((int)uVar6 != 0) {
            FUN_140003e50("BMC status, watchdog, LAN and SEL queried; read-only session.");
            uVar14 = 0;
          }
        }
      }
    }
  }
  if (DAT_1400571c4 == '\x01') {
    lVar5 = (**(code **)(DAT_140057178 + 0x30))(DAT_140057178,0,0,0x40,&local_78);
    if (((-1 < lVar5) &&
        (bVar1 = FUN_140004eb0((char *)&local_78), (int)CONCAT71(extraout_var_01,bVar1) != 0)) &&
       (uVar6 = FUN_140003af0((longlong)local_68,0x140057190,0x18), (int)uVar6 != 0)) {
      uVar2 = FUN_140003e20((undefined2 *)((longlong)&local_78 + 4));
      uVar10 = DAT_1400571c0 & 2 | uVar2 & 0xfffd;
      local_b0 = CONCAT62(local_b0._2_6_,uVar10);
      local_b8 = local_b8 & 0xffffffffffff0000;
      if (uVar10 == uVar2) {
        uVar7 = 0;
      }
      else {
        uVar7 = (**(code **)(DAT_140057178 + 0x38))(DAT_140057178,1,4,1,&local_b0);
      }
      uVar8 = (**(code **)(DAT_140057178 + 0x30))(DAT_140057178,1,4,1,&local_b8);
      FUN_140003b90("PCI_RESTORE write=");
      FUN_140003c00(uVar7,0x10);
      FUN_140003b90(" read=");
      FUN_140003c00(uVar8,0x10);
      FUN_140003b90(" after=");
      FUN_140003c00(local_b8 & 0xffff,4);
      FUN_140003b90("\r\n");
      if (-1 < (longlong)uVar8) {
        if ((short)local_b8 == (short)local_b0) {
          DAT_1400571c4 = '\0';
          _DAT_140078d74 = 1;
          goto LAB_1400021fc;
        }
      }
    }
    DAT_140057104 = 1;
    FUN_140003e50("PCI restore unconfirmed; stop testing.");
    uVar14 = 0x8000000000000007;
  }
LAB_1400021fc:
  if ((((longlong)uVar14 < 0) && (DAT_140078d68 != 0)) && ((DAT_140057104 & 1) != 0)) {
    FUN_140003e50("KCS read failed; this driver instance will not retry.");
  }
  FUN_140003420(0,0x140078cb0);
  DAT_140057100 = '\0';
  _DAT_140057080 = uVar14;
  FUN_140003b90("P1_READ_END status=");
  FUN_140003c00(uVar14,0x10);
  FUN_140003b90("\r\n");
  return uVar14;
}

