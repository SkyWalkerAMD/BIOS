
undefined4 FUN_180001950(longlong param_1,char *param_2)

{
  uint uVar1;
  int _Ch;
  longlong lVar2;
  FILE *_File;
  
  if (*(char *)(param_1 + 0x139) != '\x01') {
    return 0xfffffffb;
  }
  lVar2 = FUN_180005d00((char *)(param_1 + 0x18),"wb");
  *(longlong *)(param_1 + 0x120) = lVar2;
  if (lVar2 != 0) {
    _File = (FILE *)FUN_180005d00(param_2,"rb");
    if (_File != (FILE *)0x0) {
      uVar1 = FUN_180005b1c((longlong)*(FILE **)(param_1 + 0x120));
      while (uVar1 == 0) {
        _Ch = FID_conflict_getc(_File);
        FID_conflict_putc(_Ch,*(FILE **)(param_1 + 0x120));
        uVar1 = FUN_180005b1c(*(longlong *)(param_1 + 0x120));
      }
      fclose(*(FILE **)(param_1 + 0x120));
      fclose(_File);
      return 0;
    }
    fclose(*(FILE **)(param_1 + 0x120));
    return 0xfffffff2;
  }
  return 0xfffffff9;
}

