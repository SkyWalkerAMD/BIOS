
void FUN_000189a4(void)

{
  longlong lVar1;
  ulonglong uVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  longlong *plVar6;
  
  uVar4 = 0;
  if ((DAT_000baa68 == 0) && ((2 < DAT_000afd00 || ((DAT_000afd00 == 2 && (DAT_000b014a != '\0')))))
     ) {
    *(undefined1 *)(DAT_000afdd0 + 0x5a) = 0;
    *(undefined1 *)(DAT_000afdd0 + 0x59) = 1;
  }
  else {
    if (DAT_000afdd0 != 0) {
      (*(code *)PTR_FUN_00093cf8)(DAT_000afdd0,1);
      DAT_000afdd0 = 0;
    }
    if (DAT_000afec8 != 0) {
      lVar3 = DAT_000afec8;
      uVar2 = uVar4;
      uVar5 = uVar4;
      if (DAT_000afec4 != 0) {
        do {
          if ((*(longlong *)(uVar2 + lVar3) != 0) &&
             (lVar1 = (**(code **)(DAT_000afbc8 + 0x70))(*(longlong *)(uVar2 + lVar3)),
             lVar3 = DAT_000afec8, lVar1 == 0)) {
            *(undefined8 *)(uVar2 + DAT_000afec8) = 0;
            lVar3 = DAT_000afec8;
          }
          plVar6 = (longlong *)(lVar3 + 8 + uVar2);
          if ((plVar6 != (longlong *)0x0) && (*plVar6 != 0)) {
            (**(code **)(DAT_000afbc8 + 0x48))(*plVar6);
            *plVar6 = 0;
            lVar3 = DAT_000afec8;
          }
          uVar5 = uVar5 + 1;
          uVar2 = uVar2 + 0x10;
        } while (uVar5 < DAT_000afec4);
      }
      if (lVar3 != 0) {
        (**(code **)(DAT_000afbc8 + 0x48))();
        DAT_000afec8 = 0;
      }
      DAT_000afec4 = 0;
    }
    NA06_3f5cc(4);
    FUN_0001c100();
    FUN_0001c078();
    FUN_00018c58();
    FUN_00040b3c();
    DAT_00093ad0 = 0xffff;
    DAT_00093ac8 = 0xffff;
    if (DAT_000afff0 != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
      DAT_000afff0 = 0;
    }
    if (DAT_000baa88 != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
      DAT_000baa88 = 0;
      DAT_000afe54 = 0;
    }
    if (DAT_000b0150 != 0) {
      uVar2 = DAT_000b8d38;
      lVar3 = DAT_000b0150;
      uVar5 = uVar4;
      if (DAT_000b8d38 != 0) {
        do {
          plVar6 = (longlong *)(lVar3 + 8 + uVar5);
          if ((*plVar6 != 0) && (plVar6 != (longlong *)0x0)) {
            (**(code **)(DAT_000afbc8 + 0x48))(*plVar6);
            uVar2 = DAT_000b8d38;
            *plVar6 = 0;
            lVar3 = DAT_000b0150;
          }
          uVar4 = uVar4 + 1;
          uVar5 = uVar5 + 0x18;
        } while (uVar4 < uVar2);
      }
      if (lVar3 != 0) {
        (**(code **)(DAT_000afbc8 + 0x48))();
        DAT_000b0150 = 0;
      }
      DAT_000b8d38 = 0;
    }
    while (DAT_000baa30 != 0) {
      DAT_000baa30 = *(longlong *)(DAT_000baa30 + 0x10);
      (**(code **)(DAT_000afbc8 + 0x48))();
    }
    if (DAT_000b8c88 != 0) {
      (**(code **)(DAT_000afbc8 + 0x150))(&DAT_000b8c88,&DAT_00093778,&PTR_LAB_00093d80,0);
    }
  }
  return;
}

