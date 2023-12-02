# main
```c
undefined8 main(undefined4 param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "Time for a classic! i\'m not going to GIVE you the flag, instead you give me the flag and I\' ll tell you if its right or wrong!"
      );
  fgets(local_58,0x40,stdin);
  iVar1 = secret_proprietary_super_advanced_password_checker(local_58,param_1);
  if (iVar1 == 0) {
    puts("Hey you got it! nice work!");
  }
  else {
    puts("wrong password! cya");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
# secret_proprietary_super_advanced_password_checker
```c
int secret_proprietary_super_advanced_password_checker(long param_1,undefined4 param_2)

{
  FILE *__stream;
  size_t sVar1;
  long in_FS_OFFSET;
  int local_78;
  int local_74;
  char local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  __stream = fopen("flag.txt","r");
  fread(local_68,1,0x40,__stream);
  fclose(__stream);
  local_78 = 0;
  for (local_74 = 0;
      ((sVar1 = strlen(local_68), (ulong)(long)local_74 < sVar1 && (local_78 == 0)) &&
      (local_78 = super_proprietary_super_advanced_password_checker_hasher
                            ((int)*(char *)(param_1 + local_74),(int)local_68[local_74],param_2),
      local_68[local_74] != '}')); local_74 = local_74 + 1) {
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return local_78;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

# super_proprietary_super_advanced_password_checker_hasher

```c
int super_proprietary_super_advanced_password_checker_hasher(char param_1,char param_2,int param _3)

{
  char cVar1;
  long in_FS_OFFSET;
  long local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  cVar1 = (char)((int)param_1 - (int)param_2);
  if ((int)param_1 - (int)param_2 < 1) {
    cVar1 = -cVar1;
  }
  local_20 = 0;
  local_28 = (long)(cVar1 * param_3);
  syscall();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(&local_28,0);
  }
  return (int)cVar1;
}
```

