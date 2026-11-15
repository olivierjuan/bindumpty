
void _1f1782bc1340dc3df7b07ab3ddc6d05c(long param_1,undefined8 param_2)

{
  int iVar1;
  long lVar2;
  undefined1 local_418 [1024];
  long local_18;
  
  if (param_1 != 0) {
    lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x10);
    if (((*(code **)(lVar2 + 0x368) != (code *)0x0) && (*(long *)(lVar2 + 0x298) != 0)) &&
       (*(long *)(lVar2 + 0x5e0) != 0)) {
      lVar2 = (**(code **)(lVar2 + 0x368))(param_1,param_2,local_418);
      if (lVar2 != 0) {
        iVar1 = (**(code **)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x298))
                          (param_1,0,0,&local_18,0);
        if ((iVar1 == 0) && (local_18 != 0)) {
          (**(code **)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x5e0))(param_1,local_18,lVar2);
        }
      }
    }
  }
  return;
}

