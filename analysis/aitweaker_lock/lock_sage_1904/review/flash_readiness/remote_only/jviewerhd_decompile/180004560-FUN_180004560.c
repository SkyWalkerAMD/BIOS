
int FUN_180004560(longlong *param_1,char *param_2)

{
  int iVar1;
  FILE *_File;
  void *_Memory;
  size_t sVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint local_res8 [4];
  uint local_res18 [2];
  uint local_res20 [2];
  
  if ((char)param_1[3] == '\0') {
    return -5;
  }
  _File = (FILE *)FUN_180005d00(param_2,"wb");
  if (_File == (FILE *)0x0) {
    return -0xe;
  }
  iVar1 = (**(code **)(*param_1 + 0x40))(param_1,local_res8,local_res18);
  if (iVar1 == 0) {
    if (local_res8[0] < 0x201) {
      iVar1 = 0;
      *(undefined1 *)(param_1 + 2) = 0;
      *(undefined4 *)((longlong)param_1 + 0xc) = 0;
      _Memory = (void *)thunk_FUN_18000506c((ulonglong)(local_res8[0] * local_res18[0]));
      if (_Memory == (void *)0x0) {
        fclose(_File);
        iVar1 = -6;
      }
      else {
        iVar4 = 0;
        iVar3 = 0;
        uVar5 = local_res18[0] >> 2;
        if (0 < (int)local_res18[0]) {
          do {
            if ((char)param_1[2] == '\x01') {
              iVar1 = -0x12;
              break;
            }
            iVar1 = (**(code **)(*param_1 + 0x48))
                              (param_1,iVar4,uVar5,local_res20,
                               (longlong)(int)(iVar4 * local_res8[0]) + (longlong)_Memory);
            if (iVar1 != 0) break;
            iVar4 = iVar4 + local_res20[0] / local_res8[0];
            for (; iVar3 < iVar4; iVar3 = iVar3 + (int)sVar2) {
              sVar2 = fwrite((void *)((longlong)(int)(iVar3 * local_res8[0]) + (longlong)_Memory),
                             (ulonglong)local_res8[0],(longlong)(iVar4 - iVar3),_File);
              if ((int)sVar2 == 0) {
                iVar1 = -0xf;
                break;
              }
            }
            *(uint *)((longlong)param_1 + 0xc) = (uint)(iVar3 * 100) / (local_res18[0] - 1);
          } while (iVar3 < (int)local_res18[0]);
        }
        free(_Memory);
        fclose(_File);
      }
      return iVar1;
    }
    iVar1 = -6;
  }
  fclose(_File);
  return iVar1;
}

