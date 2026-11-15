
undefined8 FUN_00003f00(undefined *param_1,undefined8 param_2,undefined8 param_3,short param_4)

{
  bool bVar1;
  undefined8 uVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined8 *puVar8;
  short **ppsVar9;
  undefined1 uVar10;
  ushort *puVar11;
  longlong lVar12;
  undefined1 local_res20 [8];
  short *local_2f8;
  undefined8 local_2f0 [3];
  ushort local_2d8 [40];
  ushort local_288 [124];
  undefined8 local_190 [47];
  
  if (((ushort)(param_4 + 0xe0b5U) < 2) && (*(longlong *)(DAT_000153f8 + 8) != 0x1000)) {
    if (*(longlong *)(DAT_000153f8 + 8) == 1) {
      puVar11 = local_288;
      bVar1 = FUN_00009aac(1,param_2,param_3,puVar11);
      if (!bVar1) goto LAB_00003f41;
      if (param_4 == 0x1f4b) {
        FUN_000002e0((undefined8 *)local_2d8,local_190,0x50);
        puVar8 = local_2f0;
        lVar3 = FUN_0000785c(local_2d8,&local_2f8,puVar8,puVar11);
        uVar10 = SUB81(puVar11,0);
        if ((lVar3 < 0) || (*local_2f8 != 0)) {
          FUN_0000631c(local_190);
          lVar4 = FUN_000097d0(param_1,0xf8,(ulonglong)puVar8,uVar10);
          ppsVar9 = &local_2f8;
          lVar3 = 0;
          local_2f8 = (short *)0x0;
          puVar7 = &DAT_0000a380;
          lVar12 = DAT_00015458;
          lVar5 = (**(code **)(DAT_00015458 + 0x140))();
          if (-1 < lVar5) {
            lVar3 = 0xf9;
            puVar6 = (undefined *)FUN_000097d0(param_1,0xf9,(ulonglong)ppsVar9,(char)lVar12);
            puVar7 = param_1;
            if ((lVar4 != 0) && (puVar6 != (undefined *)0x0)) {
              ppsVar9 = (short **)CONCAT71((int7)((ulonglong)ppsVar9 >> 8),1);
              (**(code **)(local_2f8 + 0x10))(puVar6,lVar4,ppsVar9,local_res20);
              lVar3 = DAT_00015458;
              (**(code **)(DAT_00015458 + 0x48))(lVar4);
              (**(code **)(DAT_00015458 + 0x48))();
              puVar7 = puVar6;
            }
          }
          bVar1 = FUN_00009ba8(puVar7,lVar3,(longlong)ppsVar9,local_288);
          if (!bVar1) goto LAB_00003f41;
        }
      }
    }
    uVar2 = 0;
  }
  else {
LAB_00003f41:
    uVar2 = 0x8000000000000003;
  }
  return uVar2;
}

