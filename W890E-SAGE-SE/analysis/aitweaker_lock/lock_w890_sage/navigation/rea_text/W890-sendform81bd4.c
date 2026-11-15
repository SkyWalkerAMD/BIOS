
void FUN_00081bd4(short param_1,longlong *param_2)

{
  longlong lVar1;
  short *psVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined *puVar6;
  longlong lVar7;
  undefined8 *puVar8;
  undefined8 uVar9;
  undefined2 *puVar10;
  ushort local_res10 [4];
  undefined2 local_38;
  undefined2 local_36;
  undefined1 local_34;
  short *local_30;
  
  local_36 = 0x20;
  local_34 = 1;
  puVar5 = (undefined8 *)0x0;
  local_res10[0] = 0;
  lVar7 = -0x7ffffffffffffff1;
  FUN_0000fd6c(0xffff0008,&LAB_0004f000,0,0);
  (*(code *)**(undefined8 **)(DAT_000afbc0 + 0x30))(*(undefined8 **)(DAT_000afbc0 + 0x30),0);
  lVar1 = (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093628,0,&DAT_000b8b40);
  if (-1 < lVar1) {
    puVar8 = &DAT_000b8b50;
    puVar6 = &DAT_00093278;
    lVar1 = (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093278,0);
    if ((-1 < lVar1) && (psVar2 = (short *)FUN_00059b50(puVar6,0x42), psVar2 != (short *)0x0)) {
      FUN_0005be04(1,0x3050004,puVar8,&DAT_000938a8,0);
      (*(code *)*DAT_000b8b50)();
      puVar8 = puVar5;
      do {
        (*(code *)DAT_000b8b50[2])(7);
        FUN_000015c0((undefined8 *)psVar2,0x42);
        puVar10 = &local_38;
        local_38 = 0xb7;
        local_30 = psVar2;
        lVar1 = (**(code **)(DAT_000b8b40 + 0x88))(DAT_000babe8,param_1,puVar10,1,0);
        if (lVar1 != 0) break;
        if (*local_30 == 0) {
          lVar7 = -0x7ffffffffffffffe;
        }
        else {
          puVar10 = (undefined2 *)0x0;
          lVar7 = FUN_00082048((longlong)psVar2,param_2,'\0');
          if (lVar7 == 0) break;
          if (lVar7 == -0x7fffffffffffffeb) {
            puVar3 = FUN_0004bc70(DAT_000babe8,0xb8,(short *)0x0);
            uVar9 = 0;
            puVar4 = FUN_0004bc70(DAT_000babe8,0xb9,(short *)0x0);
            puVar10 = (undefined2 *)CONCAT71((int7)((ulonglong)uVar9 >> 8),1);
            (**(code **)(DAT_000b8b40 + 0x20))(puVar3,puVar4,puVar10,0);
            break;
          }
        }
        puVar3 = puVar5;
        if (param_1 != -1) {
          puVar3 = FUN_0004bc70(DAT_000babe8,param_1,(short *)0x0);
        }
        uVar9 = 0;
        puVar4 = FUN_0004bc70(DAT_000babe8,0x13,(short *)0x0);
        puVar10 = (undefined2 *)CONCAT71((int7)((ulonglong)uVar9 >> 8),1);
        (**(code **)(DAT_000b8b40 + 0x20))(puVar3,puVar4,puVar10,0);
        puVar8 = (undefined8 *)((longlong)puVar8 + 1);
      } while (puVar8 <= &IMAGE_DOS_HEADER_00000000.e_cblp);
      lVar1 = (**(code **)*param_2)((undefined8 *)*param_2,local_res10);
      if ((((-1 < lVar1) && (lVar7 != 0)) && ((local_res10[0] & 0x200) == 0)) &&
         (puVar8 < &IMAGE_DOS_HEADER_00000000.e_crlc)) {
        do {
          (*(code *)DAT_000b8b50[2])(7);
          FUN_000015c0((undefined8 *)psVar2,0x42);
          puVar10 = &local_38;
          local_38 = 0xb6;
          local_30 = psVar2;
          lVar1 = (**(code **)(DAT_000b8b40 + 0x88))(DAT_000babe8,param_1,puVar10,1,0);
          if (lVar1 != 0) break;
          if (*local_30 == 0) {
            lVar7 = -0x7ffffffffffffffe;
          }
          else {
            puVar10 = (undefined2 *)CONCAT71((int7)((ulonglong)puVar10 >> 8),1);
            lVar7 = FUN_00082048((longlong)psVar2,param_2,'\x01');
            if (lVar7 == 0) break;
            if (lVar7 == -0x7fffffffffffffeb) {
              puVar8 = FUN_0004bc70(DAT_000babe8,0xb8,(short *)0x0);
              uVar9 = 0;
              puVar3 = FUN_0004bc70(DAT_000babe8,0xb9,(short *)0x0);
              puVar10 = (undefined2 *)CONCAT71((int7)((ulonglong)uVar9 >> 8),1);
              (**(code **)(DAT_000b8b40 + 0x20))(puVar8,puVar3,puVar10,0);
              break;
            }
          }
          if (puVar8 != (undefined8 *)((longlong)&IMAGE_DOS_HEADER_00000000.e_cp + 1)) {
            puVar3 = puVar5;
            if (param_1 != -1) {
              puVar3 = FUN_0004bc70(DAT_000babe8,param_1,(short *)0x0);
            }
            uVar9 = 0;
            puVar4 = FUN_0004bc70(DAT_000babe8,0x13,(short *)0x0);
            puVar10 = (undefined2 *)CONCAT71((int7)((ulonglong)uVar9 >> 8),1);
            (**(code **)(DAT_000b8b40 + 0x20))(puVar3,puVar4,puVar10,0);
          }
          puVar8 = (undefined8 *)((longlong)puVar8 + 1);
        } while (puVar8 <= (undefined8 *)((longlong)&IMAGE_DOS_HEADER_00000000.e_cp + 1));
      }
      FUN_000015c0((undefined8 *)psVar2,0x42);
      (**(code **)(DAT_000afbc8 + 0x48))(psVar2);
      if (lVar7 != 0) {
        if (param_1 != -1) {
          puVar5 = FUN_0004bc70(DAT_000babe8,param_1,(short *)0x0);
        }
        uVar9 = 0;
        puVar8 = FUN_0004bc70(DAT_000babe8,0xb4,(short *)0x0);
        puVar10 = (undefined2 *)CONCAT71((int7)((ulonglong)uVar9 >> 8),1);
        (**(code **)(DAT_000b8b40 + 0x20))(puVar5,puVar8,puVar10,0);
        FUN_00010648(0x80000002,0x3051004);
      }
      (*(code *)DAT_000b8b50[1])();
      FUN_0005be04(1,0x3050005,puVar10,&DAT_000938a8,0);
    }
  }
  return;
}

