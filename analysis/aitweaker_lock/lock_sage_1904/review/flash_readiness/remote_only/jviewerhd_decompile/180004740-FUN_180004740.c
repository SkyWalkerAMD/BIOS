
int FUN_180004740(longlong *param_1,char *param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  FILE *_File;
  void *_Memory;
  size_t sVar4;
  int iVar5;
  int iVar6;
  uint local_res8 [2];
  uint local_res18 [4];
  
  if ((char)param_1[3] == '\0') {
    return -5;
  }
  _File = (FILE *)FUN_180005d00(param_2,"rb");
  if (_File == (FILE *)0x0) {
    return -0xe;
  }
  iVar1 = fseek(_File,0,2);
  if (iVar1 != 0) {
    fclose(_File);
    return -0x10;
  }
  uVar2 = ftell(_File);
  iVar1 = fseek(_File,0,0);
  if (iVar1 != 0) {
    fclose(_File);
    return -0x10;
  }
  iVar1 = (**(code **)(*param_1 + 0x40))(param_1,local_res18,local_res8);
  if (iVar1 == 0) {
    if ((local_res18[0] == 0x200) && (uVar2 >> 9 == local_res8[0])) {
      _Memory = (void *)thunk_FUN_18000506c((ulonglong)(local_res8[0] << 9));
      if (_Memory == (void *)0x0) {
        fclose(_File);
        iVar1 = -6;
      }
      else {
        iVar1 = 0;
        uVar2 = local_res8[0] >> 2;
        *(undefined1 *)(param_1 + 2) = 0;
        *(undefined4 *)((longlong)param_1 + 0xc) = 0;
        iVar6 = 0;
        iVar5 = 0;
        if (0 < (int)local_res8[0]) {
          do {
            if ((char)param_1[2] == '\x01') {
              iVar1 = -0x12;
              break;
            }
            sVar4 = fread((void *)((longlong)(int)(iVar6 * local_res18[0]) + (longlong)_Memory),
                          (ulonglong)local_res18[0],(longlong)(int)uVar2,_File);
            uVar3 = (uint)sVar4;
            if (uVar3 == 0) break;
            if (uVar3 == uVar2) {
              uVar2 = local_res8[0] >> 2;
            }
            else {
              uVar2 = uVar2 - uVar3;
            }
            iVar6 = iVar6 + uVar3;
            for (; iVar5 < iVar6; iVar5 = iVar5 + (iVar6 - iVar5)) {
              iVar1 = (**(code **)(*param_1 + 0x50))
                                (param_1,iVar5,iVar6 - iVar5,
                                 (longlong)(int)(iVar5 * local_res18[0]) + (longlong)_Memory);
              if (iVar1 != 0) break;
            }
            *(uint *)((longlong)param_1 + 0xc) = (uint)(iVar5 * 100) / (local_res8[0] - 1);
          } while (iVar5 < (int)local_res8[0]);
        }
        free(_Memory);
        fclose(_File);
      }
    }
    else {
      fclose(_File);
      iVar1 = -0x11;
    }
  }
  else {
    fclose(_File);
  }
  return iVar1;
}

