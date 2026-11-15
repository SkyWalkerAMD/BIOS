

/* WARNING: Type propagation algorithm not settling */



word ******* FUN_0000d090(word *******param_1,undefined8 param_2,undefined8 param_3,char param_4)



{

  short sVar1;

  short *psVar2;

  char cVar3;

  char cVar4;

  word ************ppppppppppppwVar5;

  ulonglong uVar6;

  longlong lVar7;

  word ************ppppppppppppwVar8;

  ulonglong uVar9;

  short *psVar10;

  undefined8 uVar11;

  word ************ppppppppppppwVar12;

  undefined4 *puVar13;

  longlong lVar14;

  longlong lVar15;

  byte *pbVar16;

  word ************ppppppppppppwVar17;

  word ************ppppppppppppwVar18;

  short *local_res8;

  undefined8 local_res10;

  undefined8 local_res18;

  char local_res20;

  word ************local_e8;

  byte *local_e0;

  word ***********local_d8;

  word ***********local_d0;

  undefined4 local_c8;

  undefined4 local_c4;

  undefined4 local_c0;

  undefined4 local_bc;

  undefined8 local_b8;

  word ***********local_b0;

  undefined4 local_a8;

  undefined4 local_a4;

  undefined4 local_a0;

  undefined4 local_9c;

  int local_98;

  int local_94;

  word ************local_90;

  word ************local_88;

  byte *local_80;

  undefined8 local_78;

  word ************local_70;

  longlong local_68;

  longlong local_60 [4];

  

  local_a8 = 0x3677770f;

  local_b8 = 0;

  local_res8 = (short *)((ulonglong)local_res8 & 0xffffffffffffff00);

  ppppppppppppwVar17 = (word ************)0x8000000000000003;

  local_a4 = 0x43b2efb2;

  local_a0 = 0x2b3aeb8;

  ppppppppppppwVar18 = (word ************)0x0;

  local_9c = 0x824860e9;

  local_c8 = 0x8c12a959;

  local_c4 = 0x436270bc;

  local_c0 = 0x5b837b4;

  local_bc = 0x6e91a114;

  local_68 = 0;

  local_60[1] = 0;

  local_e0 = (byte *)0x0;

  local_b0 = (word ***********)0x0;

  local_80 = (byte *)0x0;

  local_d0 = (word ***********)0x0;

  local_98 = 0;

  if (param_1 == (word *******)0x0) {

    return (word *******)(word ************)0x8000000000000002;

  }

  lVar14 = (longlong)(int)DAT_001801a0;

  local_94 = (int)DAT_001801a0;

  DAT_001801a0 = 7;

  local_res10 = param_2;

  local_res18 = param_3;

  local_res20 = param_4;

  ppppppppppppwVar5 =

       (word ************)

       (**(code **)(DAT_00180188 + 0x170))(0x200,8,FUN_000017b4,0,&DAT_00109fd8,&local_78);

  if ((longlong)ppppppppppppwVar5 < 0) {

    return (word *******)ppppppppppppwVar5;

  }

  (**(code **)(DAT_00180188 + 0x68))(local_78);

  (**(code **)(DAT_00180188 + 0x70))(local_78);

  FUN_000b1c80(1,0x3051001);

  FUN_00049f4c();

  if (DAT_0018026c == 7) {

    if (((*(byte *)param_1 & 0x7f) == 5) && (*(char *)((longlong)param_1 + 1) == '\x01')) {

      FUN_00003c38(0xffff0009,&LAB_0004ba00);

      FUN_0004ac08();

    }

    else {

      FUN_00003c38(0xffff000b,&LAB_0004ba18);

      if (DAT_001802d8 != 0) {

        (**(code **)(DAT_00180188 + 0x70))();

        DAT_001802d8 = 0;

      }

      if (DAT_001802e8 != 0) {

        (**(code **)(DAT_00180188 + 0x70))();

        DAT_001802e8 = 0;

      }

      if ((((DAT_00180200 != 0) && (DAT_00190698 != 0)) && (DAT_001906a0 != 0)) &&

         ((lVar14 = *(longlong *)(*(longlong *)(DAT_00180200 + 0x18) + 8),

          DAT_00190698 != *(uint *)(lVar14 + 4) || (DAT_001906a0 != *(uint *)(lVar14 + 8))))) {

        FUN_00009248(&DAT_00190698,&DAT_001906a0);

      }

      FUN_0000176c(&local_a8);

      FUN_0000cfb0();

    }

    local_res8 = (short *)0x0;

    lVar14 = (**(code **)(DAT_00180188 + 0x140))(&DAT_0010c3c0,0,&local_res8);

    if (-1 < lVar14) {

      ppppppppppppwVar17 = (word ************)(**(code **)local_res8)();

    }

    local_e8 = ppppppppppppwVar17;

    if ((((ulonglong)*param_1 & 0x7f) == 5) && (*(char *)((longlong)param_1 + 1) == '\x01')) {

      FUN_000493b0();

    }

LAB_0000d2ee:

    FUN_0000176c(&local_c8);

    return (word *******)local_e8;

  }

  if (((*(byte *)param_1 & 0x7f) == 5) && (*(char *)((longlong)param_1 + 1) == '\x01')) {

    if ((DAT_001801a8 != (undefined8 *)0x0) &&

       ((*(code *)*DAT_001801a8)(DAT_001801a8,&local_98,0,0), local_98 != 0)) {

      (*(code *)DAT_001801a8[1])(DAT_001801a8,0);

      FUN_0004ab40();

    }

    FUN_00003c38(0xffff0009,&LAB_0004ba00);

    FUN_0004ac08();

    local_e8 = (word ************)FUN_0000a094();

    if (-1 < (longlong)local_e8) {

      local_e8 = (word ************)(**(code **)(DAT_001802d0 + 0x20))(DAT_001802d0,param_1,0,0);

    }

    FUN_000493b0();

    if ((longlong)local_e8 < 0) {

      FUN_00049498((longlong)local_e8);

    }

    FUN_00003c38(0xffff000a,&LAB_0004ba0c);

    DAT_001801a0 = lVar14;

    goto LAB_0000d2ee;

  }

  uVar6 = (**(code **)(DAT_00180188 + 0x18))(0x1f);

  (**(code **)(DAT_00180188 + 0x20))(4);

  ppppppppppppwVar5 = (word ************)0x0;

  if (*(char *)param_1 == '\x04') {

    if (*(char *)((longlong)param_1 + 1) == '\x01') {

      param_1 = (word *******)FUN_0000dc68((longlong)param_1);

      local_res8 = (short *)CONCAT71(local_res8._1_7_,1);

      ppppppppppppwVar5 = (word ************)0x0;

      ppppppppppppwVar18 = (word ************)0x0;

    }

    else {

      if ((*(char *)((longlong)param_1 + 1) != '\x04') || (DAT_001802f2 != '\0')) goto LAB_0000d4cd;

      local_d8 = (word ***********)FUN_0000e828((longlong)param_1);

      if (local_d8 != (word ***********)0x0) {

        DAT_001802f2 = 1;

        local_e8 = (word ************)FUN_0000c888((short *)local_d8);

        FUN_000013d0((longlong *)&local_d8);

        lVar15 = 0;

        if ((longlong)local_e8 < 0) {

          psVar10 = (short *)((longlong)param_1 + 4);

          sVar1 = *psVar10;

          psVar2 = psVar10;

          lVar7 = lVar15;

          while (sVar1 != 0) {

            psVar2 = psVar2 + 1;

            lVar7 = lVar7 + 1;

            sVar1 = *psVar2;

          }

          ppppppppppppwVar18 = (word ************)FUN_000014c8(lVar7 * 2 + 2);

          local_d8 = (word ***********)ppppppppppppwVar18;

          if (ppppppppppppwVar18 != (word ************)0x0) {

            sVar1 = *psVar10;

            psVar2 = psVar10;

            while (sVar1 != 0) {

              psVar2 = psVar2 + 1;

              lVar15 = lVar15 + 1;

              sVar1 = *psVar2;

            }

            FUN_000b07bc((short *)ppppppppppppwVar18,lVar15 + 1,psVar10);

            local_e8 = (word ************)FUN_0000c888((short *)ppppppppppppwVar18);

            FUN_000013d0((longlong *)&local_d8);

          }

        }

        DAT_001802f2 = '\0';

        DAT_001801a0 = lVar14;

        goto LAB_0000dc3a;

      }

    }

  }

  else {

LAB_0000d4cd:

    uVar9 = FUN_0000e99c((char *)param_1);

    if ((char)uVar9 != '\0') {

      local_e0 = FUN_0000ea3c((word *)param_1,(longlong *)&local_d0,&local_b0);

      ppppppppppppwVar18 = (word ************)local_d0;

      if (local_e0 != (byte *)0x0) {

        local_80 = (byte *)FUN_0000f804((byte *)local_d0);

      }

      ppppppppppppwVar5 = (word ************)local_b0;

      if (ppppppppppppwVar18 != (word ************)0x0) {

        param_1 = (word *******)ppppppppppppwVar18;

      }

    }

  }

  cVar3 = FUN_0000fa54((byte *)param_1);

  if (cVar3 != '\0') {

    FUN_0000176c(&local_a8);

    FUN_00003c38(0xffff000b,&LAB_0004ba18);

  }

  if ((((DAT_00180200 != 0) && (DAT_00190698 != 0)) && (DAT_001906a0 != 0)) &&

     ((lVar14 = *(longlong *)(*(longlong *)(DAT_00180200 + 0x18) + 8),

      DAT_00190698 != *(uint *)(lVar14 + 4) || (DAT_001906a0 != *(uint *)(lVar14 + 8))))) {

    FUN_00009248(&DAT_00190698,&DAT_001906a0);

  }

  uVar11 = 0;

  FUN_000b1c80(1,0x3090001);

  pbVar16 = local_e0;

  ppppppppppppwVar12 = (word ************)CONCAT71((int7)((ulonglong)uVar11 >> 8),1);

  local_e8 = (word ************)

             (**(code **)(DAT_00180188 + 200))

                       (ppppppppppppwVar12,DAT_00180190,param_1,local_e0,ppppppppppppwVar5,&local_b8

                       );

  if ((longlong)local_e8 < 0) {

    lVar15 = -0x7ffffffffffffffd;

    FUN_00049598((longlong)local_e8);

    ppppppppppppwVar12 = (word ************)param_1;

    lVar14 = FUN_000490a4(param_1);

    if ((DAT_001801b8 == 6) &&

       (ppppppppppppwVar12 = (word ************)param_1, cVar3 = FUN_0000fa54((byte *)param_1),

       cVar3 != '\0')) {

      lVar15 = 0;

      if (lVar14 < 0) {

        local_d8 = (word ***********)0x0;

        local_90 = (word ************)param_1;

        lVar7 = (**(code **)(DAT_00180188 + 0xb8))(&DAT_0010a5f8,&local_90,&local_d8);

        if (lVar7 < 0) {

          ppppppppppppwVar12 = (word ************)&DAT_0010a248;

          local_90 = (word ************)param_1;

          lVar7 = (**(code **)(DAT_00180188 + 0xb8))(&DAT_0010a248,&local_90,&local_d8);

          if (-1 < lVar7) goto LAB_0000d688;

        }

        else {

          ppppppppppppwVar12 = (word ************)&DAT_0010a398;

          local_90 = (word ************)param_1;

          lVar7 = (**(code **)(DAT_00180188 + 0xb8))();

          if (lVar7 < 0) {

LAB_0000d688:

            ppppppppppppwVar12 = (word ************)local_d8;

            (**(code **)(DAT_00180188 + 0x108))(local_d8,0,0,1);

            goto LAB_0000d6a1;

          }

        }

        lVar15 = -0x7ffffffffffffffd;

        goto LAB_0000d6a1;

      }

LAB_0000d6ad:

      uVar11 = 0;

      FUN_000b1c80(1,0x3090001);

      ppppppppppppwVar12 = (word ************)CONCAT71((int7)((ulonglong)uVar11 >> 8),1);

      local_e8 = (word ************)

                 (**(code **)(DAT_00180188 + 200))

                           (ppppppppppppwVar12,DAT_00180190,param_1,0,0,&local_b8);

      pbVar16 = local_e0;

      if (-1 < (longlong)local_e8) goto LAB_0000d8bd;

      ppppppppppppwVar12 = local_e8;

      FUN_00049598((longlong)local_e8);

    }

    else {

LAB_0000d6a1:

      if ((-1 < lVar14) || (-1 < lVar15)) goto LAB_0000d6ad;

    }

    pbVar16 = local_e0;

    if ((longlong)local_e8 < 0) {

      local_b0 = (word ***********)0x0;

      ppppppppppppwVar12 = (word ************)param_1;

      local_70 = (word ************)param_1;

      ppppppppppppwVar8 = (word ************)FUN_0000e33c((char *)param_1);

      ppppppppppppwVar5 = ppppppppppppwVar8;

      if (ppppppppppppwVar8 == (word ************)0x0) {

        ppppppppppppwVar12 = (word ************)&DAT_0010a398;

        local_e8 = (word ************)

                   (**(code **)(DAT_00180188 + 0xb8))(&DAT_0010a398,&local_70,&local_88);

        ppppppppppppwVar5 = local_88;

      }

      local_88 = ppppppppppppwVar5;

      ppppppppppppwVar5 = local_88;

      if ((((-1 < (longlong)local_e8) &&

           (ppppppppppppwVar12 = local_70, ((ulonglong)*local_70 & 0x7f) == 0x7f)) &&

          (*(byte *)((longlong)local_70 + 1) == 0xff)) ||

         (ppppppppppppwVar8 != (word ************)0x0)) {

        uVar9 = FUN_0000e9ec((char *)param_1);

        if ((char)uVar9 == '\0') {

          ppppppppppppwVar8 =

               (word ************)

               FUN_000015e8((longlong)ppppppppppppwVar5,u__EFI_BOOT_BOOTX64_EFI_0010c400);

          local_d0 = (word ***********)ppppppppppppwVar8;

        }

        else {

          ppppppppppppwVar12 = (word ************)FUN_000b210c((char *)param_1);

          ppppppppppppwVar8 = (word ************)FUN_000014c8(ppppppppppppwVar12);

          ppppppppppppwVar18 = ppppppppppppwVar8;

          local_d0 = (word ***********)ppppppppppppwVar8;

          if (ppppppppppppwVar8 == (word ************)0x0) goto LAB_0000d8a4;

          uVar9 = FUN_000b210c((char *)param_1);

          ppppppppppppwVar5 = ppppppppppppwVar8;

          FUN_001073e0(ppppppppppppwVar8,param_1,uVar9);

        }

        ppppppppppppwVar18 = (word ************)0x0;

        ppppppppppppwVar12 = ppppppppppppwVar5;

        if (ppppppppppppwVar8 != (word ************)0x0) {

          lVar14 = (**(code **)(DAT_00180188 + 0x98))(local_88,&DAT_0010a5f8,&local_b0);

          if ((-1 < lVar14) &&

             (local_60[0] = FUN_0000151c((ulonglong)*(uint *)((longlong)local_b0[1] + 0xc)),

             local_60[0] != 0)) {

            (*(code *)local_b0[3])

                      (local_b0,*(undefined4 *)local_b0[1],0,

                       *(undefined4 *)((longlong)local_b0[1] + 0xc),local_60[0]);

            FUN_000013d0(local_60);

          }

          FUN_000b1c80(1,0x3090001);

          local_e8 = (word ************)

                     (**(code **)(DAT_00180188 + 200))

                               (1,DAT_00180190,ppppppppppppwVar8,0,0,&local_b8);

          if ((longlong)local_e8 < 0) {

            FUN_00049598((longlong)local_e8);

          }

          ppppppppppppwVar12 = &local_d0;

          FUN_000013d0((longlong *)ppppppppppppwVar12);

          pbVar16 = local_e0;

          ppppppppppppwVar18 = (word ************)local_d0;

          goto LAB_0000d8bd;

        }

      }

LAB_0000d8a4:

      local_e8 = (word ************)0x800000000000000e;

      pbVar16 = local_e0;

    }

  }

LAB_0000d8bd:

  cVar3 = local_res20;

  if ((local_res20 == '\x01') && ((longlong)local_e8 < 0)) {

    FUN_000ad938(ppppppppppppwVar12,0x3051002);

  }

  if ((char)local_res8 != '\0') {

    (**(code **)(DAT_00180188 + 0x48))(param_1);

  }

  if ((longlong)local_e8 < 0) {

    cVar3 = FUN_0000fa54((byte *)param_1);

    if (cVar3 != '\0') {

      FUN_00003c38(0xffff000c,FUN_000017b4);

      FUN_0000176c(&local_c8);

    }

    FUN_000079b0();

  }

  else {

    lVar14 = (**(code **)(DAT_00180188 + 0x98))(local_b8,&DAT_00109ef8,&local_68);

    if ((-1 < lVar14) && (*(int *)(local_68 + 0x50) != 1)) {

      DAT_001801a0 = (longlong)local_94;

      if (4 < uVar6) {

        (**(code **)(DAT_00180188 + 0x18))(uVar6);

      }

      return (word *******)(word ************)0x8000000000000003;

    }

    lVar14 = *(longlong *)(DAT_00180180 + 0x40);

    if (lVar14 != 0) {

      (**(code **)(lVar14 + 0x40))(lVar14,0);

    }

    lVar14 = (**(code **)(DAT_00180188 + 0x98))(local_b8,&DAT_00109ef8);

    if (-1 < lVar14) {

      *(undefined8 *)(local_res8 + 0x1c) = local_res10;

      *(int *)(local_res8 + 0x18) = (int)local_res18;

    }

    cVar4 = FUN_0000fa54((byte *)param_1);

    if (cVar4 == '\0') {

      FUN_00003c38(0xffff000b,&LAB_0004ba18);

      FUN_0000176c(&local_a8);

    }

    FUN_0000cfb0();

    local_res8 = (short *)FUN_0000130c(u_BootCurrent_0016c140,&DAT_00109f58,(undefined4 *)0x0,

                                       local_60 + 1);

    if (local_res8 != (short *)0x0) {

      psVar10 = FUN_0000c098(*local_res8);

      if ((psVar10 != (short *)0x0) && ((*(uint *)(psVar10 + 2) & 0x100) == 0)) {

        ppppppppppppwVar17 = (word ************)(**(code **)(DAT_00180188 + 0x100))(300,0,0,0);

        DAT_001802f1 = '\x01';

      }

      FUN_000013d0((longlong *)&local_res8);

    }

    FUN_000b1c80(1,0x3090002);

    local_e8 = (word ************)(**(code **)(DAT_00180188 + 0xd0))(local_b8,0);

    if ((-1 < (longlong)ppppppppppppwVar17) && (DAT_001802f1 != '\0')) {

      (**(code **)(DAT_00180188 + 0x100))(0,0,0,0);

      DAT_001802f1 = '\0';

    }

    if (DAT_001802d8 != 0) {

      (**(code **)(DAT_00180188 + 0x70))();

      DAT_001802d8 = 0;

    }

    if (DAT_001802e8 != 0) {

      (**(code **)(DAT_00180188 + 0x70))();

      DAT_001802e8 = 0;

    }

    FUN_00003c38(0xffff000c,FUN_000017b4);

    puVar13 = &local_c8;

    FUN_0000176c(puVar13);

    FUN_000079b0();

    if ((longlong)local_e8 < 0) {

      FUN_0004ab40();

      if (cVar3 == '\x01') {

        FUN_000ad938(puVar13,0x3051003);

      }

      if (DAT_00193908 != (undefined4 *)0x0) {

        FUN_0010749e(DAT_00193908,0xb71b04,0);

      }

      lVar14 = *(longlong *)(DAT_00180180 + 0x40);

      if (lVar14 != 0) {

        (**(code **)(lVar14 + 0x40))(lVar14,0);

        (**(code **)(*(longlong *)(DAT_00180180 + 0x40) + 0x28))

                  (*(longlong *)(DAT_00180180 + 0x40),0xf);

        (**(code **)(*(longlong *)(DAT_00180180 + 0x40) + 0x30))(*(longlong *)(DAT_00180180 + 0x40))

        ;

      }

      uVar9 = DAT_0010a738 - 1;

      if (DAT_0010a7a0 == 0xffff) {

        DAT_0010a7a0 = uVar9;

      }

      DAT_0010a7a8 = 0;

      if (DAT_0010a7a0 < uVar9) {

        DAT_0010a7a0 = uVar9;

      }

    }

    else {

      FUN_0004ab40();

    }

  }

  if (pbVar16 != (byte *)0x0) {

    FUN_000013d0((longlong *)&local_e0);

  }

  if (ppppppppppppwVar18 != (word ************)0x0) {

    FUN_000013d0((longlong *)&local_d0);

  }

  if (local_80 != (byte *)0x0) {

    FUN_0000f710(local_80);

    FUN_000013d0((longlong *)&local_80);

  }

  DAT_001801a0 = (longlong)local_94;

LAB_0000dc3a:

  if (uVar6 < 5) {

    return (word *******)local_e8;

  }

  (**(code **)(DAT_00180188 + 0x18))(uVar6);

  return (word *******)local_e8;

}



