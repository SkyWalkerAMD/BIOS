/* {"status": "resolved", "address": "0x4c88", "name": "FUN_00004c88"} */

longlong FUN_00004c88(longlong param_1)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  char cVar4;
  longlong lVar5;
  longlong lVar6;
  ulonglong uVar7;
  wchar_t *pwVar8;
  longlong *plVar9;
  uint uVar10;
  ulonglong uVar12;
  longlong lVar13;
  longlong lVar14;
  ulonglong uVar15;
  ulonglong local_res18 [2];
  ulonglong uVar11;
  
  lVar13 = 0;
  local_res18[0] = 0;
  pwVar8 = u_TlsCaCertificate_00008f60;
  lVar5 = (**(code **)(DAT_00009058 + 0x48))
                    (u_TlsCaCertificate_00008f60,&DAT_00008cb0,0,local_res18,0);
  if ((lVar5 < 0) && (lVar5 != -0x7ffffffffffffffb)) {
    lVar6 = FUN_000068bc();
    cVar4 = (**(code **)(lVar6 + 8))(&DAT_00008d00,0x10002);
    if (cVar4 == '\x01') {
      lVar5 = lVar13;
    }
  }
  else {
    lVar6 = FUN_00006eb0(pwVar8,local_res18[0]);
    if (lVar6 == 0) {
      lVar5 = -0x7ffffffffffffff7;
    }
    else {
      lVar5 = (**(code **)(DAT_00009058 + 0x48))
                        (u_TlsCaCertificate_00008f60,&DAT_00008cb0,0,local_res18,lVar6);
      if (-1 < lVar5) {
        lVar5 = -0x7ffffffffffffffe;
        uVar11 = local_res18[0] & 0xffffffff;
        bVar3 = false;
        if ((int)local_res18[0] != 0) {
          do {
            uVar10 = (uint)uVar11;
            if (uVar10 < 0x1c) goto LAB_00004ee6;
            plVar9 = (longlong *)((local_res18[0] - uVar11) + lVar6);
            uVar1 = *(uint *)(plVar9 + 2);
            if ((uVar1 < 0x1c) || (uVar10 < uVar1)) goto LAB_00004ee6;
            if ((*plVar9 != DAT_00008d60) || (plVar9[1] != DAT_00008d68)) {
              lVar5 = -0x7ffffffffffffffd;
              goto LAB_00004ee6;
            }
            if (*(int *)((longlong)plVar9 + 0x14) != 0) goto LAB_00004ee6;
            uVar2 = *(uint *)(plVar9 + 3);
            if (0x10 < uVar2) {
              bVar3 = true;
            }
            if (((ulonglong)uVar1 - 0x1c) % (ulonglong)uVar2 != 0) goto LAB_00004ee6;
            lVar13 = lVar13 + ((ulonglong)uVar1 - 0x1c) / (ulonglong)uVar2;
            uVar11 = (ulonglong)(uVar10 - uVar1);
          } while (uVar10 - uVar1 != 0);
          if ((bVar3) && (lVar13 != 0)) {
            bVar3 = false;
            uVar11 = local_res18[0];
            lVar13 = lVar6;
            do {
              if ((uint)uVar11 < *(uint *)(lVar13 + 0x10)) break;
              uVar12 = (ulonglong)*(uint *)(lVar13 + 0x18);
              lVar14 = lVar13 + 0x1c + (ulonglong)*(uint *)(lVar13 + 0x14);
              uVar7 = (((ulonglong)*(uint *)(lVar13 + 0x10) - (ulonglong)*(uint *)(lVar13 + 0x14)) -
                      0x1c) / uVar12;
              uVar15 = 0;
              if (uVar7 != 0) {
                do {
                  lVar5 = (*(code *)**(undefined8 **)(param_1 + 0x368))
                                    (*(undefined8 **)(param_1 + 0x368),2,lVar14 + 0x10,uVar12 - 0x10
                                    );
                  if (lVar5 < 0) break;
                  uVar12 = (ulonglong)*(uint *)(lVar13 + 0x18);
                  uVar15 = (ulonglong)((int)uVar15 + 1);
                  lVar14 = lVar14 + uVar12;
                  bVar3 = true;
                } while (uVar15 < uVar7);
              }
              uVar10 = (uint)uVar11 - *(uint *)(lVar13 + 0x10);
              uVar11 = (ulonglong)uVar10;
              lVar13 = lVar13 + (ulonglong)*(uint *)(lVar13 + 0x10);
            } while (uVar10 != 0);
            if (bVar3) {
              lVar5 = 0;
            }
          }
        }
      }
LAB_00004ee6:
      (**(code **)(DAT_00009050 + 0x48))(lVar6);
    }
  }
  return lVar5;
}

