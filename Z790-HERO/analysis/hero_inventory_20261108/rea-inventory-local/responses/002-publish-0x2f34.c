
longlong FUN_00002f34(undefined8 *param_1,undefined8 param_2)

{
  char cVar1;
  ulonglong uVar2;
  longlong lVar3;
  uint local_res10;
  undefined4 uStackX_14;
  ulonglong local_18;
  longlong local_10;
  
  _local_res10 = CONCAT44((int)((ulonglong)param_2 >> 0x20),3);
  cVar1 = FUN_00002ec0();
  if (cVar1 == '\0') {
    lVar3 = 0;
  }
  else {
    local_10 = 0;
    local_18 = 1;
    uVar2 = FUN_0001888c((longlong *)&local_18);
    if ((longlong)uVar2 < 0) {
      lVar3 = -0x7ffffffffffffff7;
    }
    else {
      FUN_00018950(&local_18,s_OData_Version_00019b80,&DAT_00019b78);
      lVar3 = FUN_00018af0(param_1,7,u__redfish_v1_oem_ami_inventory_cr_0001a650,&local_18,0,0,
                           (ulonglong *)0x0,(longlong *)0x0,(ulonglong *)0x0,&local_res10);
      if ((-1 < lVar3) && ((0x15 < local_res10 || ((0x200088U >> (local_res10 & 0x1f) & 1) == 0))))
      {
        lVar3 = -0x7fffffffffffffe8;
      }
    }
    if (local_10 != 0) {
      FUN_000188d4(&local_18);
    }
  }
  return lVar3;
}

