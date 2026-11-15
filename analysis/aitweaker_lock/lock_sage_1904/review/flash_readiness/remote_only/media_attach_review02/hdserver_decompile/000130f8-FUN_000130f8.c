
void FUN_000130f8(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  byte local_15;
  int local_14 [2];
  
  iVar3 = DAT_00013244;
  if (*(int *)(DAT_00013244 + 0x130) <= param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001325c,DAT_00013250,DAT_00013258);
    return;
  }
  iVar1 = DAT_00013244 + param_1 * 4;
  iVar2 = *(int *)(DAT_00013248 + 0x1e4);
  *(undefined4 *)(iVar1 + 0x134) = 0;
  *(undefined4 *)(iVar1 + 0x144) = 0;
  local_15 = 0;
  local_14[0] = 0;
  *(undefined4 *)(iVar1 + 0x154) = 1;
  if (iVar2 != 1) {
    iVar1 = get_service_configurations(DAT_0001324c,iVar3 + 0x164);
    if (iVar1 != 0) {
      puts(DAT_0001326c);
      return;
    }
    iVar3 = iVar3 + 0x193;
    iVar1 = isNotEditable(iVar3,1);
    if (iVar1 != 0) {
      getNotEditableData(iVar3,1,local_14);
    }
    iVar3 = get_active_session(4,&local_15);
    if (iVar3 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013254,DAT_00013250,DAT_00013268);
    }
    local_15 = local_15 + 1;
    if (local_14[0] < (int)(uint)local_15) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013264,DAT_00013250,DAT_00013260);
      return;
    }
    iVar3 = set_active_session(4);
    if (iVar3 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013254,DAT_00013250,0x348);
    }
  }
  return;
}

