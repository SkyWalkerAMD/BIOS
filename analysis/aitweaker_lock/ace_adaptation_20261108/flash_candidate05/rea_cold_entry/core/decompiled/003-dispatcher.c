
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong Candidate_ACE1904_dispatcher(void)

{
  undefined **ppuVar1;
  bool bVar2;
  undefined *puVar3;
  char cVar4;
  longlong lVar5;
  byte *pbVar6;
  ulonglong uVar7;
  longlong *plVar8;
  undefined8 *puVar9;
  undefined **ppuVar10;
  code *pcVar11;
  longlong *local_res8;
  
  if (DAT_00017b20 == '\0') {
    DAT_00017b20 = '\x01';
    pcVar11 = FUN_0000f788;
    lVar5 = FUN_00009354(0x200,0x10,0xf788,0,(longlong *)&DAT_00015b70,&local_res8);
    if (-1 < lVar5) {
      lVar5 = -0x7ffffffffffffff2;
LAB_00009b96:
      do {
        puVar3 = PTR_LOOP_00016b78;
        if ((undefined **)PTR_LOOP_00016b78 != &PTR_LOOP_00016b78) {
          if ((*(longlong *)(PTR_LOOP_00016b78 + 0x68) == 0) && (PTR_LOOP_00016b78[0x70] == '\0')) {
            pcVar11 = *(code **)(PTR_LOOP_00016b78 + 0x28);
            pbVar6 = FUN_00008620('\0',DAT_00017a80,(byte *)pcVar11,0,0,
                                  (undefined8 *)(PTR_LOOP_00016b78 + 0x68));
            if ((longlong)pbVar6 < 0) {
              FUN_0000e6ec((ulonglong *)&DAT_00016b60);
              if (pbVar6 == (byte *)0x800000000000001a) {
                puVar3[0x5f] = 1;
              }
              else {
                puVar3[0x60] = 1;
              }
              puVar3[0x5e] = 0;
              *(undefined8 *)(*(longlong *)puVar3 + 8) = *(undefined8 *)(puVar3 + 8);
              **(undefined8 **)(puVar3 + 8) = *(undefined8 *)puVar3;
              _DAT_00016b70 = 1;
              FUN_0000cc98(DAT_00016b68);
              goto LAB_00009b96;
            }
          }
          FUN_0000e6ec((ulonglong *)&DAT_00016b60);
          puVar3[0x5e] = 0;
          puVar3[0x60] = 1;
          *(undefined8 *)(*(longlong *)puVar3 + 8) = *(undefined8 *)(puVar3 + 8);
          **(undefined8 **)(puVar3 + 8) = *(undefined8 *)puVar3;
          _DAT_00016b70 = 1;
          uVar7 = DAT_00016b68;
          FUN_0000cc98(DAT_00016b68);
          lVar5 = 0;
          if (puVar3[0x70] == '\0') {
            puVar9 = (undefined8 *)(puVar3 + 0x68);
            FUN_00011268(uVar7,0x3040002,pcVar11,(undefined *)0x0,(undefined8 *)0x0,puVar9);
            plVar8 = (longlong *)*puVar9;
            pcVar11 = (code *)0x0;
            FUN_00008720(plVar8,(undefined8 *)0x0,(undefined8 *)0x0);
            FUN_00011268(plVar8,0x3040003,pcVar11,(undefined *)0x0,(undefined8 *)0x0,puVar9);
          }
          else {
            pcVar11 = (code *)(puVar3 + 0x18);
            FUN_0000a0f0(*(byte **)(puVar3 + 0x30),*(longlong **)(puVar3 + 0x10),(ushort *)pcVar11);
          }
          goto LAB_00009b96;
        }
        if (-1 < lVar5) {
          FUN_00009560(local_res8);
        }
        bVar2 = false;
        ppuVar10 = (undefined **)PTR_LOOP_00016b98;
        if ((undefined **)PTR_LOOP_00016b98 == &PTR_LOOP_00016b98) break;
        do {
          ppuVar1 = ppuVar10 + -1;
          if (*(char *)((longlong)ppuVar10 + 0x71) != '\0') {
            FUN_0000988c((longlong)ppuVar1);
          }
          if ((*(char *)((longlong)ppuVar10 + 0x6c) != '\0') &&
             (cVar4 = Candidate_ACE1904_evaluate_depex((longlong)ppuVar1), cVar4 != '\0')) {
            Candidate_ACE1904_schedule_with_ordering(ppuVar1);
            bVar2 = true;
          }
          ppuVar10 = (undefined **)*ppuVar10;
        } while (ppuVar10 != &PTR_LOOP_00016b98);
      } while (bVar2);
      FUN_00009760(local_res8);
      DAT_00017b20 = '\0';
    }
  }
  else {
    lVar5 = -0x7fffffffffffffec;
  }
  return lVar5;
}

