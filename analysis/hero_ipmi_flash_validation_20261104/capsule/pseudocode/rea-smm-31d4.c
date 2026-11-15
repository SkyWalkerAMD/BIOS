
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_000031d4(longlong param_1,longlong param_2,ulonglong param_3)

{
  uint *puVar1;
  uint *puVar2;
  longlong lVar3;
  ulonglong uVar4;
  int iVar5;
  undefined8 local_res8;
  uint *local_res20;
  undefined4 uVar6;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  uint *local_60;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined4 local_48;
  undefined *local_40;
  
  puVar1 = (uint *)(param_1 + 0x48);
  local_48 = 0x20;
  local_58 = _DAT_00005030;
  uStack_50 = uRam0000000000005038;
  local_40 = &DAT_00005a00;
  local_68 = 0x100;
  iVar5 = (*(uint *)(param_1 + 0x14) & 1) + 1;
  local_78 = _DAT_000052a0;
  uStack_74 = uRam00000000000052a4;
  uStack_70 = uRam00000000000052a8;
  uStack_6c = uRam00000000000052ac;
  local_60 = puVar1;
  lVar3 = (*(code *)DAT_00005a40[4])(DAT_00005a40,&DAT_00005110,&local_78);
  if (lVar3 < 0) {
    puVar2 = (uint *)(param_1 + 0x20);
    uVar4 = param_1 + 0x248;
    if (uVar4 < param_1 + 0x20 + (ulonglong)*puVar2) {
      do {
        if (*(char *)(uVar4 + 0x10) == '\0') break;
        local_60 = (uint *)(uVar4 + 0x10);
        lVar3 = (*(code *)DAT_00005a40[4])(DAT_00005a40,&DAT_00005110,&local_78);
        if (-1 < lVar3) {
          if ((*(byte *)(param_1 + 0x14) & 4) == 0) {
            local_res8 = 0x228;
            local_res20 = puVar2;
          }
          else {
            local_res8 = 0x100;
            local_res20 = puVar1;
          }
          uVar6 = 0;
          lVar3 = (*(code *)DAT_00005a40[2])
                            (DAT_00005a40,&DAT_00005030,1,&local_res20,&local_res8,&DAT_00005a00);
          if (lVar3 < 0) {
            return -0x7fffffffffffffe6;
          }
          lVar3 = (*(code *)*DAT_00005a40)
                            (DAT_00005a40,&local_78,&local_58,uVar4 + 0x110,0x100,
                             CONCAT44(uVar6,iVar5));
          break;
        }
        uVar4 = uVar4 + 0x210;
      } while (uVar4 < param_1 + 0x20 + (ulonglong)*puVar2);
    }
    if (lVar3 < 0) {
      return -0x7fffffffffffffe6;
    }
  }
  lVar3 = FUN_00002e74(param_1,param_2,param_3,&DAT_00005030);
  if (-1 < lVar3) {
    local_60 = puVar1;
    lVar3 = (*(code *)*DAT_00005a40)(DAT_00005a40,&local_78,&local_58,param_1 + 0x148,0x100,iVar5);
  }
  return lVar3;
}

