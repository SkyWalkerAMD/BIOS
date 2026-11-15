
longlong Candidate_ACE1904_post_publication_initializer(void)

{
  undefined *puVar1;
  longlong lVar2;
  undefined **ppuVar3;
  undefined8 local_res8;
  undefined8 local_res10;
  undefined8 local_res18;
  
  local_res18 = 0;
  ppuVar3 = &PTR_DAT_0006adb0;
  local_res10 = 0;
  puVar1 = PTR_DAT_0006adb0;
  while (puVar1 != (undefined *)0x0) {
    lVar2 = (**(code **)(DAT_000824c8 + 0x50))(0x200,8,&LAB_0000790c,*ppuVar3,*ppuVar3 + 8);
    if (-1 < lVar2) {
      puVar1 = *ppuVar3;
      lVar2 = (**(code **)(DAT_000824c8 + 0xa8))
                        (*(undefined8 *)(puVar1 + 0x18),*(undefined8 *)(puVar1 + 8),puVar1 + 0x28);
      if (-1 < lVar2) {
        (**(code **)(DAT_000824c8 + 0x68))(*(undefined8 *)(*ppuVar3 + 8));
      }
    }
    ppuVar3 = ppuVar3 + 1;
    puVar1 = *ppuVar3;
  }
  lVar2 = (**(code **)(DAT_000824c8 + 0x50))(0x200,8,&LAB_00007798,0,&local_res8);
  if ((-1 < lVar2) &&
     (lVar2 = (**(code **)(DAT_000824c8 + 0xa8))(&DAT_0006a6e0,local_res8,&local_res10), -1 < lVar2)
     ) {
    (**(code **)(DAT_000824c8 + 0x68))(local_res8);
  }
  return lVar2;
}

