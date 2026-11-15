
ulonglong FUN_00002014(undefined8 param_1,longlong *param_2,longlong *param_3)

{
  longlong *plVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined1 *puVar4;
  undefined8 uVar5;
  int iVar6;
  longlong *plVar7;
  byte *pbVar8;
  ulonglong uVar9;
  ulonglong local_res10;
  byte *local_res20;
  undefined1 local_68 [9];
  undefined8 local_5f;
  undefined8 local_57;
  undefined4 local_4f;
  undefined2 local_4b;
  undefined1 local_49;
  longlong local_48 [2];
  uint local_38;
  byte *local_30;
  
  local_68[0] = 0;
  local_68._1_8_ = 0;
  local_5f = 0;
  local_57 = 0;
  local_4f = 0;
  local_4b = 0;
  local_49 = 0;
  if (((param_2 == (longlong *)0x0) || (param_3 == (longlong *)0x0)) ||
     (plVar1 = param_3 + 3, *plVar1 == 0)) {
    uVar3 = 0x8000000000000002;
  }
  else {
    lVar2 = FUN_0000249c(param_2,(longlong *)&DAT_0000e0c0,0x10);
    if (lVar2 == 0) {
      local_30 = (byte *)0x0;
      local_38 = 0;
      uVar3 = FUN_00001f38(0,local_48,param_2,0);
      pbVar8 = local_30;
      if (-1 < (longlong)uVar3) {
        uVar9 = (ulonglong)local_38;
        plVar7 = (longlong *)*plVar1;
        lVar2 = FUN_0000249c(param_3,(longlong *)&DAT_0000e100,0x10);
        uVar3 = uVar9;
        if (lVar2 == 0) {
          lVar2 = FUN_0000249c(local_48,(longlong *)&DAT_0000e040,0x10);
          if (lVar2 == 0) {
            local_res10 = (ulonglong)*(uint *)(param_3 + 2);
            plVar7 = (longlong *)local_68;
            FUN_00005160(1,plVar1,(longlong)&local_res10,(longlong)local_68);
            uVar3 = 0x20;
          }
          else {
            lVar2 = FUN_0000249c(local_48,(longlong *)&DAT_0000e080,0x10);
            if (lVar2 == 0) {
              pbVar8 = &DAT_0000ebe0;
              uVar3 = 0x100;
              local_res20 = &DAT_0000ebe0;
              local_res10 = 0x100;
              FUN_00009210();
              if ((local_30 == (byte *)0x0) || (uVar9 == 0)) {
                iVar6 = -1;
              }
              else {
                puVar4 = FUN_0000695c(local_30,uVar9);
                uVar5 = FUN_00004ed0((longlong)puVar4,(longlong *)&local_res20,&local_res10);
                iVar6 = (int)uVar5;
                uVar3 = local_res10;
                pbVar8 = local_res20;
              }
              FUN_00009210();
              if (iVar6 != 0) {
                return 0x800000000000001a;
              }
            }
          }
        }
        lVar2 = FUN_0000249c((longlong *)pbVar8,plVar7,uVar3);
        uVar3 = -(ulonglong)(lVar2 != 0) & 0x800000000000001a;
      }
    }
    else {
      uVar3 = 0x8000000000000003;
    }
  }
  return uVar3;
}

