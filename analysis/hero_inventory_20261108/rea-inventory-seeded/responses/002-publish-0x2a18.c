
/* WARNING: Removing unreachable block (ram,0x00002e6e) */

ulonglong PublishInventory_from_disassembly
                    (undefined8 *param_1,longlong param_2,longlong param_3,char *param_4)

{
  byte bVar1;
  longlong *plVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined1 *puVar7;
  longlong lVar8;
  undefined8 *puVar9;
  char *pcVar10;
  undefined1 *puVar11;
  longlong *plVar12;
  byte *pbVar13;
  ulonglong uVar14;
  short *local_res10;
  longlong local_res18;
  short *local_68;
  longlong local_60;
  longlong local_58;
  undefined4 local_50;
  undefined8 *local_48;
  undefined8 local_40;
  
  puVar5 = (undefined8 *)0x0;
  local_res10 = (short *)0x0;
  local_68 = (short *)0x0;
  local_40 = 0;
  local_res18 = param_3;
  uVar3 = (**(code **)(param_2 + 0x10))(param_2,0,&local_res10);
  if ((longlong)uVar3 < 0) {
    return uVar3;
  }
  uVar3 = (**(code **)(param_2 + 8))(param_2,s_Storage_0001a618,&local_68);
  if ((longlong)uVar3 < 0) {
    return uVar3;
  }
  puVar4 = (undefined8 *)FUN_00016b80();
  if (puVar4 != (undefined8 *)0x0) {
    *(undefined4 *)(puVar4 + 3) = 6;
    local_48 = (undefined8 *)FUN_00016b80();
    puVar6 = puVar5;
    if (local_48 != (undefined8 *)0x0) {
      *(undefined4 *)(local_48 + 3) = 5;
      puVar5 = (undefined8 *)FUN_00016b80();
      puVar6 = (undefined8 *)0x0;
      if (puVar5 != (undefined8 *)0x0) {
        *(undefined4 *)(puVar5 + 3) = 5;
        puVar6 = (undefined8 *)FUN_00016b80();
        if (puVar6 != (undefined8 *)0x0) {
          *(undefined4 *)(puVar6 + 3) = 6;
          puVar7 = FUN_00016b80();
          if (puVar7 != (undefined1 *)0x0) {
            *(undefined4 *)(puVar7 + 0x18) = 6;
            (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198e0,0,&local_40);
            FUN_00002780(param_1,local_res10);
            FUN_000011cc(param_3,(longlong)puVar6);
            local_60 = 0;
            lVar8 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198c0,0,&local_60);
            if (-1 < lVar8) {
              (**(code **)(local_60 + 8))(local_60,puVar6);
            }
            local_58 = 0;
            lVar8 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_00019920,0,&local_58);
            if (-1 < lVar8) {
              (**(code **)(local_58 + 8))(local_58,puVar6);
            }
            SerializeChassis_from_disassembly(param_3,(longlong)puVar7);
            if ((*param_4 != '\0') &&
               (uVar3 = SerializeProcessor_from_disassembly(param_3,(longlong)puVar6),
               -1 < (longlong)uVar3)) {
              *param_4 = '\0';
            }
            if (param_4[1] != '\0') {
              if (param_3 == 0) {
                uVar3 = 0x8000000000000002;
              }
              else {
                uVar3 = SerializeMemoryA_from_disassembly(param_3,(longlong)puVar6);
                if ((longlong)uVar3 < 0) goto LAB_00002c0a;
                uVar3 = SerializeMemoryB_from_disassembly(param_3,(longlong)puVar6);
              }
              if (-1 < (longlong)uVar3) {
                param_4[1] = '\0';
              }
            }
LAB_00002c0a:
            if (param_4[2] != '\0') {
              puVar9 = FUN_0000e928(param_3,(longlong)puVar6,(longlong)puVar7,(ulonglong)local_res10
                                   );
              pcVar10 = FUN_0000b5e0(local_res18,(longlong)puVar6,local_68);
              uVar3 = FUN_0001595c(local_res18,(longlong)puVar6,(longlong)puVar7,
                                   (ulonglong)local_res10);
              param_3 = local_res18;
              if (-1 < (longlong)uVar3 && (-1 < (longlong)pcVar10 && -1 < (longlong)puVar9)) {
                param_4[2] = '\0';
              }
            }
            local_50 = *(undefined4 *)(param_3 + 0x20);
            local_58 = *(longlong *)(param_3 + 0x18);
            SerializeGroupCRC_from_disassembly((uint *)&local_58,(longlong)puVar4);
            local_60 = 0;
            lVar8 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198d0,0,&local_60);
            if ((-1 < lVar8) && (lVar8 = (**(code **)(local_60 + 8))(local_60,puVar6), -1 < lVar8))
            {
              (**(code **)(local_60 + 0x10))(local_60,puVar4);
            }
            puVar11 = FUN_0001880c(s_1_8_0_0001a3d0);
            FUN_00018744((longlong)puVar4,s_RedfishVersion_0001a3d8,(longlong)puVar11);
            puVar11 = FUN_0001880c(s_1_8_a_0001a3e8);
            FUN_00018744((longlong)puVar4,s_RtpVersion_0001a3f0,(longlong)puVar11);
            plVar2 = (longlong *)local_48[2];
            if ((longlong *)local_48[2] == (longlong *)0x0) {
              local_48[2] = puVar6;
            }
            else {
              do {
                plVar12 = plVar2;
                plVar2 = (longlong *)*plVar12;
              } while ((longlong *)*plVar12 != (longlong *)0x0);
              *plVar12 = (longlong)puVar6;
              puVar6[1] = plVar12;
            }
            FUN_00018744((longlong)puVar4,s_Systems_0001a620,(longlong)local_48);
            plVar2 = (longlong *)puVar5[2];
            if ((longlong *)puVar5[2] == (longlong *)0x0) {
              puVar5[2] = puVar7;
            }
            else {
              do {
                plVar12 = plVar2;
                plVar2 = (longlong *)*plVar12;
              } while ((longlong *)*plVar12 != (longlong *)0x0);
              *plVar12 = (longlong)puVar7;
              *(longlong **)(puVar7 + 8) = plVar12;
            }
            FUN_00018744((longlong)puVar4,s_Chassis_0001a628,(longlong)puVar5);
            pbVar13 = FUN_0001784c((longlong)puVar4,0,1,(longlong *)0x0);
            uVar14 = 0;
            if (pbVar13 != (byte *)0x0) {
              bVar1 = *pbVar13;
              uVar3 = uVar14;
              while (bVar1 != 0) {
                uVar3 = uVar3 + 1;
                bVar1 = pbVar13[uVar3];
              }
              uVar3 = UploadInventory_from_disassembly(param_1,(char *)pbVar13,uVar3,'\0');
              if (-1 < (longlong)uVar3) {
                do {
                  uVar3 = uVar14 + 1;
                  lVar8 = uVar14 + 1;
                  uVar14 = uVar3;
                } while (s___BootComplete__true__0001a630[lVar8] != '\0');
                uVar3 = UploadInventory_from_disassembly
                                  (param_1,s___BootComplete__true__0001a630,uVar3,'\x01');
              }
              (**(code **)(DAT_0001e070 + 0x48))(pbVar13);
            }
            if ((longlong)uVar3 < 0) {
              param_4[0] = '\x01';
              param_4[1] = '\x01';
              param_4[2] = '\x01';
            }
            if (local_res10 != (short *)0x0) {
              (**(code **)(DAT_0001e070 + 0x48))();
            }
            if (local_68 == (short *)0x0) {
              return uVar3;
            }
            (**(code **)(DAT_0001e070 + 0x48))();
            return uVar3;
          }
        }
      }
    }
    FUN_00016bcc(puVar4);
    if (local_48 != (undefined8 *)0x0) {
      FUN_00016bcc(local_48);
    }
    if (puVar5 != (undefined8 *)0x0) {
      FUN_00016bcc(puVar5);
    }
    if (puVar6 != (undefined8 *)0x0) {
      FUN_00016bcc(puVar6);
    }
  }
  if (local_res10 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  if (local_68 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  return 0x8000000000000009;
}

