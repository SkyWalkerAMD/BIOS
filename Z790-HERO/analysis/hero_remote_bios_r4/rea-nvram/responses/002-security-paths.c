/* 0x1140 */

char * entry(longlong *param_1,longlong param_2)

{
  char *pcVar1;
  
  FUN_0000117c(param_1,param_2);
  pcVar1 = FUN_0000225c(param_1,param_2);
  if ((longlong)pcVar1 < 0) {
    FUN_0000167c();
  }
  return pcVar1;
}


/* 0xbe94 */

undefined8
FUN_0000bde8(ushort *param_1,longlong *param_2,undefined8 param_3,ulonglong param_4,
            longlong *param_5)

{
  ulonglong uVar1;
  undefined8 uVar2;
  longlong lVar3;
  
  uVar1 = FUN_0000c478(param_1,param_2);
  if ((char)uVar1 != '\x01') {
    return 0x8000000000000003;
  }
  if (DAT_00013308 != 3) {
    uVar2 = FUN_0000c530(param_5,param_4);
    if ((int)uVar2 == 0) {
      if ((param_4 != 6) || (lVar3 = FUN_0000b1ac(param_5,(longlong *)&DAT_000132d0,6), lVar3 != 0))
      {
        FUN_0000bd3c();
        return 0x8000000000000006;
      }
    }
    else if ((int)uVar2 == 3) {
      if (DAT_0001330d == '\x01') {
        DAT_00013308 = DAT_00013308 + 1;
      }
      else {
        DAT_00013308 = 0;
      }
      FUN_0000bd3c();
      return 0x800000000000001a;
    }
    FUN_0000bd94();
    DAT_00013308 = 0;
    return 0x800000000000005f;
  }
  return 0x800000000000000f;
}


/* 0xc420 */

undefined1 FUN_0000cffc(longlong *param_1,longlong *param_2)

{
  longlong lVar1;
  undefined1 uVar2;
  
  lVar1 = FUN_0000b1ac(param_2,&DAT_00011010,0x10);
  uVar2 = 0;
  if (lVar1 == 0) {
    lVar1 = FUN_0000cf9c(param_1,(longlong *)&DAT_000120c0);
    uVar2 = 0;
    if (lVar1 == 0) {
      uVar2 = 1;
    }
  }
  return uVar2;
}


/* 0xd86c */

ulonglong FUN_0000d79c(longlong *param_1,longlong *param_2,uint *param_3,longlong *param_4,
                      ulonglong *param_5,longlong *param_6,ulonglong param_7,byte *param_8)

{
  byte bVar1;
  ulonglong uVar2;
  uint uVar3;
  ulonglong *in_stack_ffffffffffffffe8;
  
  uVar3 = *param_3;
  if ((uVar3 & 0x10) == 0) {
    bVar1 = *param_8;
    if (((uVar3 & 0x30) == 0) && ((bVar1 & 0x30) == 0)) {
      return 0;
    }
    if ((uVar3 & 0x30) == 0x30) {
      return 0x8000000000000002;
    }
    if (((((bVar1 & 0x30) != 0) && (uVar3 != 0)) && ((bVar1 & 0x30 & uVar3) == 0)) ||
       ((uVar3 = bVar1 & 0x30 | uVar3, *param_5 == 0 || (*param_4 == 0)))) {
      return 0x800000000000001a;
    }
    if (DAT_00013310 != 0) {
      if ((uVar3 & 0x20) == 0) {
        uVar2 = FUN_0000e1e0(param_1,param_2,uVar3,param_4,param_5,(longlong)param_6,
                             in_stack_ffffffffffffffe8,(longlong)param_8);
        return uVar2;
      }
      uVar2 = FUN_0000dcbc(param_1,param_2,uVar3,param_4,param_5,param_6,param_7,(longlong)param_8);
      return uVar2;
    }
  }
  return 0x8000000000000003;
}


/* 0xd9a9 */

longlong FUN_0000d87c(undefined8 param_1,undefined8 param_2,longlong *param_3,ulonglong param_4)

{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  undefined1 uVar4;
  longlong lVar5;
  longlong *local_res18;
  ulonglong local_res20;
  longlong local_28;
  longlong *local_20;
  
  local_28 = 0;
  local_res18 = param_3;
  local_res20 = param_4;
  lVar3 = FUN_0000cae8((ushort *)&DAT_000120c0,&DAT_00011010,(uint *)0x0,&local_20,&local_28);
  if (((-1 < lVar3) && (local_20 != (longlong *)0x0)) && (local_28 != 0)) {
    uVar1 = *(uint *)((longlong)local_20 + 0x14);
    lVar3 = FUN_0000b1ac(local_20,(longlong *)&DAT_000112b0,0x10);
    if (lVar3 == 0) {
      uVar4 = 0xb;
      lVar5 = 0;
      lVar3 = 0;
    }
    else {
      lVar3 = FUN_0000b1ac(local_20,&DAT_000111a0,0x10);
      if (lVar3 != 0) {
        return -0x7fffffffffffffe6;
      }
      lVar5 = (longlong)local_20 + (ulonglong)uVar1 + 0x2c;
      uVar4 = 8;
      lVar3 = (ulonglong)*(uint *)(local_20 + 3) - 0x10;
    }
    uVar2 = *(uint *)(local_20 + 3);
    lVar3 = (**(code **)(DAT_00013310 + 8))
                      (DAT_00013310,param_1,param_2,lVar5,lVar3,&local_res18,&local_res20,uVar4,2);
    if (lVar3 < 0) {
      return lVar3;
    }
    if (((ulonglong)uVar2 - 0x10 == local_res20) &&
       (lVar3 = FUN_0000b1ac((longlong *)((longlong)local_20 + (ulonglong)uVar1 + 0x2c),local_res18,
                             local_res20), lVar3 == 0)) {
      return 0;
    }
  }
  return -0x7fffffffffffffe6;
}


/* 0xdafd */

longlong FUN_0000d9c8(ushort *param_1,longlong *param_2,undefined8 param_3,undefined8 param_4)

{
  bool bVar1;
  uint uVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  uint uVar8;
  ulonglong local_38;
  longlong *local_30;
  
  local_38 = 0;
  lVar3 = FUN_0000cae8(param_1,param_2,(uint *)0x0,&local_30,(longlong *)&local_38);
  if (((lVar3 < 0) || (local_30 == (longlong *)0x0)) || (local_38 == 0)) {
    lVar3 = -0x7fffffffffffffe6;
  }
  else {
    bVar1 = false;
    plVar5 = local_30;
    uVar6 = local_38;
    do {
      if ((uVar6 == 0) || (uVar2 = *(uint *)(plVar5 + 2), uVar6 < uVar2)) break;
      lVar4 = FUN_0000b1ac(plVar5,&DAT_000111a0,0x10);
      if (lVar4 == 0) {
        uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
        lVar4 = (longlong)plVar5 + (ulonglong)*(uint *)((longlong)plVar5 + 0x14) + 0x1c;
        uVar8 = 0;
        uVar2 = (uint)((((ulonglong)uVar2 - (ulonglong)*(uint *)((longlong)plVar5 + 0x14)) - 0x1c) /
                      uVar7);
        if (uVar2 != 0) {
          do {
            lVar3 = (**(code **)(DAT_00013310 + 8))
                              (DAT_00013310,param_3,param_4,lVar4 + 0x10,uVar7,&stack0x00000028,
                               &stack0x00000030,1,2);
            if (-1 < lVar3) {
              bVar1 = true;
              break;
            }
            uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
            uVar8 = uVar8 + 1;
            lVar4 = lVar4 + uVar7;
          } while (uVar8 < uVar2);
        }
      }
      uVar6 = uVar6 - *(uint *)(plVar5 + 2);
      plVar5 = (longlong *)((longlong)plVar5 + (ulonglong)*(uint *)(plVar5 + 2));
    } while (!bVar1);
    if (!bVar1) {
      lVar3 = -0x7fffffffffffffe6;
    }
  }
  return lVar3;
}


/* 0xdb13 */

longlong FUN_0000d9c8(ushort *param_1,longlong *param_2,undefined8 param_3,undefined8 param_4)

{
  bool bVar1;
  uint uVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  uint uVar8;
  ulonglong local_38;
  longlong *local_30;
  
  local_38 = 0;
  lVar3 = FUN_0000cae8(param_1,param_2,(uint *)0x0,&local_30,(longlong *)&local_38);
  if (((lVar3 < 0) || (local_30 == (longlong *)0x0)) || (local_38 == 0)) {
    lVar3 = -0x7fffffffffffffe6;
  }
  else {
    bVar1 = false;
    plVar5 = local_30;
    uVar6 = local_38;
    do {
      if ((uVar6 == 0) || (uVar2 = *(uint *)(plVar5 + 2), uVar6 < uVar2)) break;
      lVar4 = FUN_0000b1ac(plVar5,&DAT_000111a0,0x10);
      if (lVar4 == 0) {
        uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
        lVar4 = (longlong)plVar5 + (ulonglong)*(uint *)((longlong)plVar5 + 0x14) + 0x1c;
        uVar8 = 0;
        uVar2 = (uint)((((ulonglong)uVar2 - (ulonglong)*(uint *)((longlong)plVar5 + 0x14)) - 0x1c) /
                      uVar7);
        if (uVar2 != 0) {
          do {
            lVar3 = (**(code **)(DAT_00013310 + 8))
                              (DAT_00013310,param_3,param_4,lVar4 + 0x10,uVar7,&stack0x00000028,
                               &stack0x00000030,1,2);
            if (-1 < lVar3) {
              bVar1 = true;
              break;
            }
            uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
            uVar8 = uVar8 + 1;
            lVar4 = lVar4 + uVar7;
          } while (uVar8 < uVar2);
        }
      }
      uVar6 = uVar6 - *(uint *)(plVar5 + 2);
      plVar5 = (longlong *)((longlong)plVar5 + (ulonglong)*(uint *)(plVar5 + 2));
    } while (!bVar1);
    if (!bVar1) {
      lVar3 = -0x7fffffffffffffe6;
    }
  }
  return lVar3;
}


/* 0xe04c */

ulonglong FUN_0000dcbc(longlong *param_1,longlong *param_2,uint param_3,longlong *param_4,
                      ulonglong *param_5,longlong *param_6,ulonglong param_7,longlong param_8)

{
  uint uVar1;
  ushort *puVar2;
  char cVar3;
  char cVar4;
  ulonglong uVar5;
  longlong lVar6;
  undefined8 uVar7;
  byte bVar8;
  char cVar9;
  longlong lVar10;
  undefined8 in_stack_ffffffffffffff60;
  longlong *local_70;
  ulonglong local_68;
  ushort *local_60;
  longlong local_58;
  ulonglong local_50;
  ulonglong local_48;
  ushort *local_40;
  
  if ((param_3 & 0x20) == 0) {
LAB_0000dcee:
    uVar5 = 0x8000000000000002;
  }
  else {
    puVar2 = (ushort *)*param_4;
    if (0x27 < *param_5) {
      uVar1 = *(uint *)(puVar2 + 8);
      if (((ulonglong)uVar1 <= *param_5 - 0x10) && (0x17 < uVar1)) {
        local_60 = puVar2 + 0x14;
        uVar5 = (ulonglong)uVar1 + 0x10;
        lVar10 = (longlong)puVar2 + (uVar5 - (longlong)local_60);
        if ((puVar2[0xb] == 0xef1) &&
           (local_48 = uVar5, local_40 = puVar2,
           lVar6 = FUN_0000b1ac((longlong *)(puVar2 + 0xc),(longlong *)&DAT_000110f0,0x10),
           lVar6 == 0)) {
          cVar3 = FUN_0000d144();
          if (((cVar3 == '\0') || (param_6 == (longlong *)0x0)) ||
             (cVar9 = '\x01', *param_5 != uVar5)) {
            cVar9 = '\0';
          }
          if (param_6 == (longlong *)0x0) {
            local_58 = 0;
          }
          else {
            local_58 = *(longlong *)(param_8 + 8);
          }
          if (cVar9 == '\0') {
            lVar6 = FUN_0000ecb4(puVar2,(longlong *)&local_50);
            uVar5 = 0;
            if (lVar6 < 0) {
              do {
                if ((*(char *)(uVar5 + (longlong)puVar2) != '\0') && ((param_3 & 0x40) == 0))
                goto LAB_0000e04c;
                uVar5 = uVar5 + 1;
                local_50 = 0;
              } while (uVar5 < 7);
            }
            if ((param_3 & 0x40) == 0) {
              if ((((*(char *)((longlong)puVar2 + 7) != '\0') ||
                   (*(char *)((longlong)puVar2 + 0xf) != '\0')) ||
                  ((*(int *)(puVar2 + 4) != 0 || ((puVar2[6] != 0 || ((char)puVar2[7] != '\0'))))))
                 || ((param_6 != (longlong *)0x0 && (local_50 <= *(ulonglong *)(param_8 + 8)))))
              goto LAB_0000e04c;
            }
            else if ((param_6 != (longlong *)0x0) && (local_50 < *(ulonglong *)(param_8 + 8))) {
              local_50 = *(ulonglong *)(param_8 + 8);
            }
            *(ulonglong *)(param_8 + 8) = local_50;
          }
          bVar8 = 4;
          lVar6 = FUN_0000b1ac(param_2,(longlong *)&DAT_00011090,0x10);
          if (lVar6 == 0) {
            bVar8 = 2;
LAB_0000deae:
            if ((param_3 & 1) == 0) goto LAB_0000dcee;
            cVar4 = FUN_0000d1cc();
            cVar9 = cVar3;
            if (cVar4 != '\0') goto LAB_0000ded2;
LAB_0000ded4:
            uVar5 = 0;
          }
          else {
            cVar4 = FUN_0000cffc(param_1,param_2);
            if (cVar4 != '\0') {
              bVar8 = 0;
              goto LAB_0000deae;
            }
            cVar4 = FUN_0000d04c(param_1,param_2);
            if (cVar4 != '\0') {
              bVar8 = 1;
              goto LAB_0000deae;
            }
            uVar7 = FUN_0000d09c(param_1,param_2);
            if ((char)uVar7 != '\0') {
              bVar8 = 3;
              goto LAB_0000deae;
            }
LAB_0000ded2:
            if (cVar9 != '\0') goto LAB_0000ded4;
            local_70 = (longlong *)&DAT_00013340;
            uVar5 = FUN_0000db3c((short *)param_1,param_2,param_3,*param_4,*param_5,
                                 in_stack_ffffffffffffff60,&local_68);
            if ((longlong)uVar5 < 0) goto LAB_0000e04c;
            if (bVar8 < 2) {
LAB_0000e02d:
              uVar5 = FUN_0000d87c(local_60,lVar10,local_70,local_68);
LAB_0000e047:
              if ((longlong)uVar5 < 0) goto LAB_0000e04c;
            }
            else if (bVar8 == 2) {
LAB_0000dff9:
              uVar5 = FUN_0000d9c8((ushort *)&DAT_000120b8,&DAT_00011010,local_60,lVar10);
              if ((longlong)uVar5 < 0) goto LAB_0000e02d;
            }
            else {
              if (bVar8 != 3) {
                if (bVar8 == 4) {
                  uVar5 = (**(code **)(DAT_00013310 + 8))
                                    (DAT_00013310,local_60,lVar10,0,0,&local_70,&local_68,9,2);
                  if (((longlong)uVar5 < 0) ||
                     ((param_6 != (longlong *)0x0 &&
                      (lVar10 = FUN_0000b1ac((longlong *)(param_8 + 0x10),local_70,0x20),
                      lVar10 != 0)))) goto LAB_0000e04c;
                  FUN_00010220((undefined8 *)(param_8 + 0x10),local_70,0x20);
                }
                goto LAB_0000e047;
              }
              uVar5 = FUN_0000d9c8((ushort *)&DAT_00012678,(longlong *)&DAT_00011090,local_60,lVar10
                                  );
              if ((longlong)uVar5 < 0) goto LAB_0000dff9;
            }
          }
          *param_5 = *param_5 - local_48;
          *param_4 = (longlong)((longlong)local_40 + local_48);
          if (*param_5 == 0) {
            return uVar5;
          }
          if ((byte)(bVar8 - 3) < 2) {
            return uVar5;
          }
          uVar5 = FUN_0000eb20((longlong *)((longlong)local_40 + local_48),*param_5,
                               (longlong *)&local_40);
          if ((longlong)uVar5 < 0) {
            return uVar5;
          }
          if ((bVar8 != 0) || (local_40 <= IMAGE_DOS_HEADER_00000000.e_magic + 1)) {
            if ((param_3 & 0x40) == 0) {
              return uVar5;
            }
            if (bVar8 != 0) {
              uVar5 = FUN_0000d5b4((longlong *)*param_4,param_5,param_6,param_7);
              if (-1 < (longlong)uVar5) {
                return uVar5;
              }
              if (local_58 == *(longlong *)(param_8 + 8)) {
                return uVar5;
              }
              *param_5 = 0;
              return 0;
            }
          }
          goto LAB_0000dcee;
        }
      }
    }
LAB_0000e04c:
    uVar5 = 0x800000000000001a;
  }
  return uVar5;
}


/* 0xe2d1 */

undefined8
FUN_0000e1e0(longlong *param_1,longlong *param_2,uint param_3,longlong *param_4,ulonglong *param_5,
            longlong param_6,ulonglong *param_7,longlong param_8)

{
  ulonglong *puVar1;
  char cVar2;
  longlong lVar3;
  undefined8 uVar4;
  longlong lVar5;
  undefined8 local_res20;
  
  puVar1 = (ulonglong *)*param_4;
  if ((param_3 & 0x10) == 0) {
    return 0x8000000000000002;
  }
  if (*param_5 < 0x28) {
    return 0x800000000000001a;
  }
  if (*(short *)((longlong)puVar1 + 0xe) != 0xef1) {
    return 0x800000000000001a;
  }
  lVar3 = FUN_0000b1ac((longlong *)(puVar1 + 2),(longlong *)&DAT_00011180,0x10);
  if (lVar3 != 0) {
    return 0x800000000000001a;
  }
  if (*param_5 < 0x230) {
    return 0x800000000000001a;
  }
  cVar2 = FUN_0000cffc(param_1,param_2);
  if (cVar2 != '\0') {
    return 0x8000000000000002;
  }
  cVar2 = FUN_0000d04c(param_1,param_2);
  if (cVar2 != '\0') {
    return 0x8000000000000002;
  }
  lVar3 = FUN_0000b1ac(param_2,(longlong *)&DAT_00011090,0x10);
  if (lVar3 == 0) {
    return 0x8000000000000002;
  }
  uVar4 = FUN_0000d09c(param_1,param_2);
  lVar3 = param_8;
  if ((char)uVar4 != '\0') {
    return 0x8000000000000002;
  }
  if ((param_3 & 0x40) == 0) {
    if ((param_6 != 0) && (*puVar1 <= *(ulonglong *)(param_8 + 8))) {
      return 0x800000000000001a;
    }
  }
  else if ((param_6 != 0) && (*puVar1 < *(ulonglong *)(param_8 + 8))) goto LAB_0000e307;
  *(ulonglong *)(param_8 + 8) = *puVar1;
LAB_0000e307:
  param_7 = puVar1 + 6;
  lVar5 = FUN_0000e0fc(*param_4,*param_5,param_7);
  if (-1 < lVar5) {
    local_res20 = 0x100;
    uVar4 = (**(code **)(DAT_00013310 + 0x10))
                      (DAT_00013310,&DAT_00011060,1,&param_7,&local_res20,&DAT_00013380);
    if ((param_6 == 0) ||
       (lVar5 = FUN_0000b1ac((longlong *)(lVar3 + 0x10),(longlong *)&DAT_00013380,0x20), lVar5 == 0)
       ) {
      FUN_00010220((undefined8 *)(lVar3 + 0x10),(undefined8 *)&DAT_00013380,0x20);
      *param_5 = *param_5 - 0x230;
      *param_4 = (longlong)(puVar1 + 0x46);
      return uVar4;
    }
  }
  return 0x800000000000001a;
}


/* 0xeb6a */

ulonglong FUN_0000eb20(longlong *param_1,ulonglong param_2,longlong *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong *plVar8;
  
  if ((param_2 < 0x30001) && (param_1 != (longlong *)0x0)) {
    lVar7 = 0;
    uVar2 = 0x800000000000001a;
    uVar1 = *(uint *)(param_1 + 2);
    while ((uVar5 = (ulonglong)uVar1, param_2 != 0 && (uVar5 <= param_2))) {
      uVar2 = 0;
      plVar8 = (longlong *)&DAT_00011fb0;
      do {
        lVar3 = FUN_0000b1ac(param_1,plVar8,0x10);
        if (lVar3 == 0) break;
        uVar2 = uVar2 + 1;
        plVar8 = plVar8 + 2;
      } while (uVar2 < 9);
      if ((((8 < uVar2) || (uVar1 < 0x2d)) || (0x30000 < uVar1)) ||
         ((*(int *)((longlong)param_1 + 0x14) != 0 ||
          (uVar2 = (ulonglong)*(uint *)(param_1 + 3), (uVar5 - 0x1c) % uVar2 != 0)))) {
        return 0x8000000000000002;
      }
      if ((*param_1 == DAT_000111a0) && (param_1[1] == DAT_000111a8)) {
        FUN_0000aca4();
        puVar4 = FUN_0000fc70((byte *)((longlong)param_1 + 0x2c),uVar2 - 0x10);
        uVar6 = ~-(ulonglong)(puVar4 != (undefined1 *)0x0) & 0x8000000000000002;
        FUN_0000aca4();
        if ((longlong)uVar6 < 0) {
          return uVar6;
        }
      }
      lVar7 = lVar7 + 1;
      uVar6 = 0x1c;
      if (0x1c < uVar5) {
        do {
          uVar6 = uVar6 + uVar2;
        } while (uVar6 < uVar5);
      }
      param_1 = (longlong *)((longlong)param_1 + uVar5);
      uVar2 = 0;
      param_2 = param_2 - uVar5;
      uVar1 = *(uint *)(param_1 + 2);
    }
    if (param_3 != (longlong *)0x0) {
      *param_3 = lVar7;
    }
  }
  else {
    uVar2 = 0x800000000000001a;
  }
  return uVar2;
}


/* 0xec8a */

ulonglong FUN_0000eb20(longlong *param_1,ulonglong param_2,longlong *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong *plVar8;
  
  if ((param_2 < 0x30001) && (param_1 != (longlong *)0x0)) {
    lVar7 = 0;
    uVar2 = 0x800000000000001a;
    uVar1 = *(uint *)(param_1 + 2);
    while ((uVar5 = (ulonglong)uVar1, param_2 != 0 && (uVar5 <= param_2))) {
      uVar2 = 0;
      plVar8 = (longlong *)&DAT_00011fb0;
      do {
        lVar3 = FUN_0000b1ac(param_1,plVar8,0x10);
        if (lVar3 == 0) break;
        uVar2 = uVar2 + 1;
        plVar8 = plVar8 + 2;
      } while (uVar2 < 9);
      if ((((8 < uVar2) || (uVar1 < 0x2d)) || (0x30000 < uVar1)) ||
         ((*(int *)((longlong)param_1 + 0x14) != 0 ||
          (uVar2 = (ulonglong)*(uint *)(param_1 + 3), (uVar5 - 0x1c) % uVar2 != 0)))) {
        return 0x8000000000000002;
      }
      if ((*param_1 == DAT_000111a0) && (param_1[1] == DAT_000111a8)) {
        FUN_0000aca4();
        puVar4 = FUN_0000fc70((byte *)((longlong)param_1 + 0x2c),uVar2 - 0x10);
        uVar6 = ~-(ulonglong)(puVar4 != (undefined1 *)0x0) & 0x8000000000000002;
        FUN_0000aca4();
        if ((longlong)uVar6 < 0) {
          return uVar6;
        }
      }
      lVar7 = lVar7 + 1;
      uVar6 = 0x1c;
      if (0x1c < uVar5) {
        do {
          uVar6 = uVar6 + uVar2;
        } while (uVar6 < uVar5);
      }
      param_1 = (longlong *)((longlong)param_1 + uVar5);
      uVar2 = 0;
      param_2 = param_2 - uVar5;
      uVar1 = *(uint *)(param_1 + 2);
    }
    if (param_3 != (longlong *)0x0) {
      *param_3 = lVar7;
    }
  }
  else {
    uVar2 = 0x800000000000001a;
  }
  return uVar2;
}

