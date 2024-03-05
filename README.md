# import-hunter

A utility header wich allows you to hide imports in kernel.

This doesn't trigger BSOD unlike many other import hiders.

## Usage
```c
CALL( "DbgPrintEx" )( 0, 0, "Hello World!\n" );
```

## IDA Output
```c
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  union _KIDTENTRY64 *IdtBase; // rax
  __int64 v3; // rax
  __int64 v4; // rdx
  __int64 v5; // r8
  __int64 v6; // r9
  __int64 v7; // rcx
  __int64 v8; // r10
  __int64 v9; // rsi
  __int64 v10; // rbx
  __int64 v11; // r12
  __int64 v12; // rbp
  char v13; // cl
  __int64 v14; // rbp
  __int64 v15; // r11
  unsigned __int64 v16; // r14
  __int64 v18; // [rsp+28h] [rbp-50h]
  __int64 v19; // [rsp+30h] [rbp-48h]

  IdtBase = KeGetPcr()->IdtBase;
  v3 = (unsigned int)HIDWORD(*(_QWORD *)IdtBase) & 0xFFFF0000 | *(_QWORD *)IdtBase & 0xF000i64 | (*((_QWORD *)IdtBase + 1) << 32);
LABEL_2:
  v4 = 0i64;
  while ( 1 )
  {
    if ( *(_BYTE *)(v3 + v4) == 72
      && *(_BYTE *)(v3 + v4 + 1) == 0x8D
      && *(_BYTE *)(v3 + v4 + 2) == 29
      && *(_BYTE *)(v3 + v4 + 6) == 0xFF )
    {
      v5 = *(int *)(v3 + v4 + 3);
      if ( (((_WORD)v5 + (_WORD)v3 + 7 + (_WORD)v4) & 0xFFF) == 0 )
      {
        v6 = v3 + v5;
        if ( *(_WORD *)(v3 + v5 + v4 + 7) == 23117 )
          break;
      }
    }
    if ( ++v4 == 4089 )
    {
      v3 -= 4096i64;
      goto LABEL_2;
    }
  }
  v7 = v3 + v5 + *(unsigned int *)(v4 + v3 + v5 + *(int *)(v4 + v6 + 67) + 7 + 136) + 7;
  v8 = *(unsigned int *)(v4 + v7 + 24);
  if ( *(_DWORD *)(v4 + v7 + 24) )
  {
    v19 = v4 + v3 + v5 + *(unsigned int *)(v4 + v7 + 28) + 7;
    v9 = v4 + v3 + v5 + *(unsigned int *)(v4 + v7 + 32) + 7;
    v18 = v4 + v3 + v5 + *(unsigned int *)(v4 + v7 + 36) + 7;
    v10 = v3 + v4 + 7;
    v11 = 0i64;
    while ( 1 )
    {
      v12 = v5 + *(unsigned int *)(v9 + 4 * v11);
      v13 = *(_BYTE *)(v10 + v12);
      if ( v13 )
      {
        v14 = v10 + v12;
        v15 = 1i64;
        v16 = 0x1CAF4EB71B3i64;
        do
        {
          v16 = v15 * (((v13 * (__int64)v13) << (v15 & 7)) ^ v13 ^ v16 ^ 0xCBF29CE484222325ui64);
          v13 = *(_BYTE *)(v14 + v15++);
        }
        while ( v13 );
        if ( v16 == 0xF4DCA747D746B056ui64 )
          break;
      }
      if ( ++v11 == v8 )
        goto LABEL_18;
    }
    ((void (__fastcall *)(_QWORD, _QWORD, const char *))(v4
                                                       + *(unsigned int *)(v19
                                                                         + 4i64 * *(unsigned __int16 *)(v18 + 2 * v11))
                                                       + v6
                                                       + 7))(
      0i64,
      0i64,
      "Hello World!\n");
  }
  else
  {
LABEL_18:
    MEMORY[0](0i64, 0i64, "Hello World!\n");
  }
  return 0;
}
```
