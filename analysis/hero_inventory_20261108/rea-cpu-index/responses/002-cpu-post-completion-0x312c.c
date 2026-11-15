
longlong PublishCRC_from_disassembly
                   (undefined8 *param_1,undefined8 param_2,longlong param_3,char *param_4)

{
  byte bVar1;
  longlong *plVar2;
  char cVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  longlong lVar8;
  longlong *plVar9;
  byte *pbVar10;
  longlong unaff_RBX;
  int local_res10;
  undefined4 uStackX_14;
  char local_48 [16];
  ulonglong local_38;
  longlong local_30;
  
  puVar5 = (undefined8 *)0x0;
  pbVar10 = (byte *)0x0;
  _local_res10 = CONCAT44((int)((ulonglong)param_2 >> 0x20),3);
  cVar3 = FUN_00002ec0();
  if (cVar3 != '\0') {
    local_30 = 0;
    local_38 = 3;
    uVar4 = FUN_0001888c((longlong *)&local_38);
    if ((-1 < (longlong)uVar4) &&
       (puVar5 = (undefined8 *)FUN_00016b80(), puVar5 != (undefined8 *)0x0)) {
      *(undefined4 *)(puVar5 + 3) = 6;
      puVar6 = FUN_00016b80();
      if (puVar6 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar6 + 0x18) = 5;
        FUN_00018744((longlong)puVar5,s_GroupCrcList_0001a3c0,(longlong)puVar6);
        puVar7 = FUN_00016b80();
        if (puVar7 != (undefined1 *)0x0) {
          *(undefined4 *)(puVar7 + 0x18) = 6;
          if (param_4[1] == '\0') {
            uVar4 = (ulonglong)*(uint *)(param_3 + 0x1c);
          }
          else {
            uVar4 = 0;
          }
          lVar8 = FUN_000187d8(uVar4);
          FUN_00018744((longlong)puVar7,&DAT_0001a3ac,lVar8);
          plVar2 = *(longlong **)(puVar6 + 0x10);
          if (*(longlong **)(puVar6 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(puVar6 + 0x10) = puVar7;
          }
          else {
            do {
              plVar9 = plVar2;
              plVar2 = (longlong *)*plVar9;
            } while ((longlong *)*plVar9 != (longlong *)0x0);
            *plVar9 = (longlong)puVar7;
            *(longlong **)(puVar7 + 8) = plVar9;
          }
        }
        puVar7 = FUN_00016b80();
        if (puVar7 != (undefined1 *)0x0) {
          *(undefined4 *)(puVar7 + 0x18) = 6;
          if (*param_4 == '\0') {
            uVar4 = (ulonglong)*(uint *)(param_3 + 0x20);
          }
          else {
            uVar4 = 0;
          }
          lVar8 = FUN_000187d8(uVar4);
          FUN_00018744((longlong)puVar7,&DAT_0001a3b4,lVar8);
          plVar2 = *(longlong **)(puVar6 + 0x10);
          if (*(longlong **)(puVar6 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(puVar6 + 0x10) = puVar7;
          }
          else {
            do {
              plVar9 = plVar2;
              plVar2 = (longlong *)*plVar9;
            } while ((longlong *)*plVar9 != (longlong *)0x0);
            *plVar9 = (longlong)puVar7;
            *(longlong **)(puVar7 + 8) = plVar9;
          }
        }
        puVar7 = FUN_00016b80();
        if (puVar7 != (undefined1 *)0x0) {
          *(undefined4 *)(puVar7 + 0x18) = 6;
          if (param_4[2] == '\0') {
            uVar4 = (ulonglong)*(uint *)(param_3 + 0x18);
          }
          else {
            uVar4 = 0;
          }
          lVar8 = FUN_000187d8(uVar4);
          FUN_00018744((longlong)puVar7,&DAT_0001a3b8,lVar8);
          plVar2 = *(longlong **)(puVar6 + 0x10);
          if (*(longlong **)(puVar6 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(puVar6 + 0x10) = puVar7;
          }
          else {
            do {
              plVar9 = plVar2;
              plVar2 = (longlong *)*plVar9;
            } while ((longlong *)*plVar9 != (longlong *)0x0);
            *plVar9 = (longlong)puVar7;
            *(longlong **)(puVar7 + 8) = plVar9;
          }
        }
        FUN_0000301c((longlong)puVar6);
        pbVar10 = FUN_0001784c((longlong)puVar5,0,1,(longlong *)0x0);
        if (pbVar10 != (byte *)0x0) {
          uVar4 = 0;
          bVar1 = *pbVar10;
          while (bVar1 != 0) {
            uVar4 = uVar4 + 1;
            bVar1 = pbVar10[uVar4];
          }
          FUN_00018950(&local_38,s_Content_Type_0001a400,s_application_json_charset_utf_8_00019b50);
          FUN_00015c2c(local_48,10,&DAT_0001a534,uVar4);
          FUN_00018950(&local_38,s_Content_Length_0001a538,local_48);
          FUN_00018950(&local_38,s_OData_Version_00019b80,&DAT_00019b78);
          FUN_00018a80(param_1,1,u__redfish_v1_oem_ami_inventory_cr_0001a650,&local_38,
                       (char *)pbVar10,(ulonglong *)0x0,(longlong *)0x0,(ulonglong *)0x0,
                       &local_res10);
        }
      }
    }
    if (local_30 != 0) {
      FUN_000188d4(&local_38);
    }
    if (puVar5 != (undefined8 *)0x0) {
      FUN_00016bcc(puVar5);
    }
    if (pbVar10 != (byte *)0x0) {
      (**(code **)(DAT_0001e070 + 0x48))(pbVar10);
    }
  }
  return unaff_RBX;
}

