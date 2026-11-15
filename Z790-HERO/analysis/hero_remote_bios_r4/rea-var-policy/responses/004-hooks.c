/* 0xb91c actual=0xb91c */

longlong FUN_0000b91c(ushort *param_1,longlong *param_2,uint param_3,undefined *param_4,
                     undefined8 param_5,int param_6)

{
  undefined **ppuVar1;
  longlong lVar2;
  ulonglong uVar3;
  
  if (DAT_00013280 != '\0') {
    ppuVar1 = FUN_0000b4e0(param_1,param_2,'\x01');
    if ((ppuVar1 != (undefined **)0x0) && (*(short *)ppuVar1 == 1)) {
      if ((param_6 != 2) && (((ulonglong)*ppuVar1 & 0x10000) != 0)) {
        return -0x7ffffffffffffff8;
      }
      if (((((param_3 & 0x40) != 0) || (param_4 != (undefined *)0x0)) && (param_3 != 0)) &&
         (((*(int *)((longlong)ppuVar1 + 4) != 0 &&
           ((param_3 & 0xffffffbf) != *(uint *)((longlong)ppuVar1 + 4))) ||
          ((param_4 != (undefined *)0x0 && ((param_4 < ppuVar1[1] || (ppuVar1[2] < param_4)))))))) {
        return -0x7ffffffffffffffe;
      }
    }
    uVar3 = 0;
    if (DAT_00013290 != 0) {
      do {
        lVar2 = (**(code **)(DAT_00013288 + uVar3 * 8))(param_1,param_2,param_3,param_4,param_5);
        if (((lVar2 != -0x7ffffffffffffff8) || (param_6 != 2)) && (lVar2 < 0)) {
          return lVar2;
        }
        uVar3 = uVar3 + 1;
      } while (uVar3 < DAT_00013290);
    }
  }
  return 0;
}


/* 0x1f80 actual=0x1f80 */

void FUN_00001f80(undefined8 param_1)

{
  longlong lVar1;
  undefined8 local_res8;
  int local_res10 [2];
  undefined8 local_res18 [2];
  
  *(undefined1 **)(DAT_000131d8 + 0x58) = &LAB_000019e8;
  local_res8 = param_1;
  (**(code **)(DAT_000131d0 + 0x148))(&local_res8,&DAT_000110a0,0,0);
  local_res18[0] = 0;
  if (DAT_000131e0 == 0) {
    DAT_000131d0._0_1_ = 0;
    DAT_000131d0._1_1_ = 0;
    DAT_000131d0._2_1_ = 0;
    DAT_000131d0._3_1_ = 0;
    DAT_000131d0._4_1_ = 0;
    DAT_000131d0._5_1_ = 0;
    DAT_000131d0._6_1_ = 0;
    DAT_000131d0._7_1_ = 0;
    DAT_000131d8._0_1_ = 0;
    DAT_000131d8._1_1_ = 0;
    DAT_000131d8._2_1_ = 0;
    DAT_000131d8._3_1_ = 0;
    DAT_000131d8._4_1_ = 0;
    DAT_000131d8._5_1_ = 0;
    DAT_000131d8._6_1_ = 0;
    DAT_000131d8._7_1_ = 0;
  }
  lVar1 = DAT_000131d0;
  *(code **)(DAT_000131d8 + 0x60) = FUN_00001c34;
  *(undefined1 **)(lVar1 + 0xf0) = &LAB_00001cfc;
  FUN_00001c34(local_res10);
  (**(code **)(DAT_000131d0 + 0x148))(local_res18,&DAT_00011240,0,0);
  return;
}


/* 0x7050 actual=0x7050 */

char * FUN_00007050(ushort *param_1,longlong *param_2,uint param_3,undefined *param_4,
                   longlong *param_5)

{
  char cVar1;
  byte bVar2;
  char *pcVar3;
  longlong lVar4;
  undefined **ppuVar5;
  
  FUN_0000ba38();
  pcVar3 = (char *)FUN_00002fb8(param_1,param_2,param_3,param_4,(char *)param_5,
                                (longlong *)&PTR_ProtectedVariableCheck_000113b0);
  if (pcVar3 == (char *)0x8000000000000003) {
    pcVar3 = VariableSetCore(param_1,param_2,param_3,param_4,param_5);
  }
  lVar4 = -0x7ffffffffffffffd;
  ppuVar5 = &PTR_FUN_00012730;
  do {
    if (lVar4 != -0x7ffffffffffffffd) break;
    lVar4 = (*(code *)*ppuVar5)(param_1,param_2,param_3,param_4,param_5,pcVar3);
    ppuVar5 = ppuVar5 + 1;
  } while (*ppuVar5 != (undefined *)0x0);
  lVar4 = 5;
  do {
    out(0xed,0x55);
    out(0xed,0xaa);
    out(0xed,0x55);
    out(0xed,0xaa);
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  out(0x2e,7);
  out(0x2f,0xb);
  out(0x2e,7);
  cVar1 = in(0x2f);
  out(0x2e,0x87);
  out(0x2e,0x87);
  out(0x2e,7);
  out(0x2f,0xb);
  out(0x2e,0xe6);
  bVar2 = in(0x2f);
  out(0x2e,7);
  out(0x2f,0xb);
  out(0x2e,0xe6);
  out(0x2f,bVar2 & 0xbf);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0x30);
  bVar2 = in(0x2f);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0x30);
  out(0x2f,bVar2 | 1);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0xf6);
  out(0x2f,0);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0xf7);
  bVar2 = in(0x2f);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0xf7);
  out(0x2f,bVar2 & 0xef);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0x30);
  bVar2 = in(0x2f);
  out(0x2e,7);
  out(0x2f,8);
  out(0x2e,0x30);
  out(0x2f,bVar2 & 0xfe);
  if (cVar1 == -1) {
    out(0x2e,0xaa);
  }
  return pcVar3;
}

