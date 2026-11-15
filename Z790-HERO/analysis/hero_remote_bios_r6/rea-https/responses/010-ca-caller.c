/* {"status": "resolved", "address": "0x4ff0", "name": "FUN_00004ff0"} */

longlong FUN_00004ff0(longlong param_1)

{
  undefined4 *puVar1;
  char cVar2;
  longlong lVar3;
  
  *(undefined8 *)(param_1 + 0x350) = *(undefined8 *)(param_1 + 0x118);
  puVar1 = (undefined4 *)(param_1 + 0x348);
  *(undefined4 *)(param_1 + 0x344) = 0;
  *puVar1 = 1;
  *(undefined4 *)(param_1 + 0x34c) = 0;
  lVar3 = FUN_000068bc();
  cVar2 = (**(code **)(lVar3 + 8))(&DAT_00008d00,0x10002);
  if (cVar2 == '\x01') {
    *puVar1 = 0;
  }
  *(undefined4 *)(param_1 + 0x358) = 0;
  lVar3 = (*(code *)**(undefined8 **)(param_1 + 0x360))
                    (*(undefined8 **)(param_1 + 0x360),1,(undefined4 *)(param_1 + 0x344));
  if ((-1 < lVar3) &&
     (lVar3 = (*(code *)**(undefined8 **)(param_1 + 0x360))
                        (*(undefined8 **)(param_1 + 0x360),5,puVar1,4), -1 < lVar3)) {
    lVar3 = FUN_000068bc();
    cVar2 = (**(code **)(lVar3 + 8))(&DAT_00008d00,0x10002);
    if (cVar2 != '\x01') {
      lVar3 = FUN_000068bc();
      cVar2 = (**(code **)(lVar3 + 8))(&DAT_00008d00,0x10003);
      if ((cVar2 == '\0') &&
         (lVar3 = (*(code *)**(undefined8 **)(param_1 + 0x360))
                            (*(undefined8 **)(param_1 + 0x360),0xb,(undefined4 *)(param_1 + 0x34c),
                             0xc), lVar3 < 0)) {
        return lVar3;
      }
    }
    lVar3 = (*(code *)**(undefined8 **)(param_1 + 0x360))
                      (*(undefined8 **)(param_1 + 0x360),7,(undefined4 *)(param_1 + 0x358),4);
    if (((-1 < lVar3) &&
        (((lVar3 = FUN_00004f08(param_1), -1 < lVar3 || (lVar3 == -0x7ffffffffffffff2)) &&
         (lVar3 = FUN_00004c88(param_1), -1 < lVar3)))) &&
       (lVar3 = FUN_000049d4(param_1), lVar3 < 0)) {
      FUN_00004bf4(param_1);
    }
  }
  return lVar3;
}

