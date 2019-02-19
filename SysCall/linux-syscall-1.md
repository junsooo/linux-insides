리눅스 커널에서의 시스템 콜 Part 1.
================================================================================

인트로
--------------------------------------------------------------------------------

지금부터 [linux-insides](https://0xax.gitbooks.io/linux-insides/content/) 책에서의 새로운 챕터가 시작됩니다. 제목에서 알 수 있듯이 이 챕터에서는 리눅스 커널의 [시스템 콜](https://en.wikipedia.org/wiki/System_call) 개념에 대해 설명할 것입니다. 이 장의 주제 선택은 우발적인 것이 아닙니다. 이전 [챕터](https://0xax.gitbooks.io/linux-insides/content/Interrupts/index.html)에서는 인터럽트와 인터럽트 핸들링에 대해 배웠습니다. 시스템 콜의 개념은 앞의 인터럽트 개념과 매우 유사합니다. 이는 시스템 콜을 구현하는 가장 일반적인 방법이 소프트웨어 인터럽트를 이용하는 것이기 때문입니다. 이 챕터에서는 시스템 콜 개념과 관련된 여러 측면을 공부할 것입니다. 예를 들어, 유저 스페이스(사용자 공간userspace)에서 시스템 호출이 발생할 때 어떤 일이 일어나는지 배울겁니다. 추가로, 리눅스 커널에서의 시스템 콜 핸들러, 예로 [VDSO](https://en.wikipedia.org/wiki/VDSO) 및 [vsyscall](https://lwn.net/Articles/446528/) 개념과 그 밖의 여러 가지 핸들러의 구현을 볼 것입니다.

리눅스 시스템 콜 구현을 공부하기 전에 시스템 콜에 대한 몇 가지 이론을 알고있는 것이 좋습니다. 다음 단락에서 해보죠.

시스템 콜이 뭐예요?
--------------------------------------------------------------------------------

시스템 콜은 커널의 서비스를 제공받기 위한 유저 스페이스의 요청일 뿐입니다. 맞습니다. 운영 체제 커널은 많은 서비스를 제공합니다. 프로그램이 파일에 뭔가를 쓰거나 읽으려 할 때, [소켓](https://en.wikipedia.org/wiki/Network_socket) 연결을 위해 listen을 시작할 때, 디렉토리를 생성하거나 삭제할 때, 심지어는 해당 작업을 끝낼 때 프로그램이 시스템 호출을 사용합니다. 다시 말하면, 시스템 콜은 유저 스페이스의 프로그램이 일부 요청들을 처리하기 위해 호출하는 커널 스페이스에 작성되어 있는 [C언어](https://en.wikipedia.org/wiki/C_%28programming_language%29) 함수일 뿐입니다.

리눅스 커널은 이러한 함수들의 세트를 제공하며 각 아키텍처에서 자체적인 세트를 제공합니다. 예를 들어, [x86_64](https://en.wikipedia.org/wiki/X86-64) 아키텍처는 [322](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl) 개의 시스템 콜을 제공하고 [x86](https://en.wikipedia.org/wiki/X86) 아키텍처는 [358](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_32.tbl)개의 다른 시스템 콜을 제공합니다. 다시 말하지만, 시스템 호출은 단지 함수일 뿐입니다. 어셈블리 프로그래밍 언어로 작성된 간단한 Hello world 예제를 살펴보시죠:

```assembly
.data

msg:
    .ascii "Hello, world!\n"
    len = . - msg

.text
    .global _start

_start:
	movq  $1, %rax
    movq  $1, %rdi
    movq  $msg, %rsi
    movq  $len, %rdx
    syscall

    movq  $60, %rax
    xorq  %rdi, %rdi
    syscall
```

위 명령을 다음과 같이 컴파일 할 수 있습니다:

```
$ gcc -c test.S
$ ld -o test test.o
```

그리고 다음과 같이 실행할 수 있습니다:

```
./test
Hello, world!
```

좋습니다. 우리가 여기서 무엇을 알 수 있을까요? 이 간단한 코드는 리눅스 `x86_64` 아키텍처용 `Hello World` 어셈블리 프로그램에 해당합니다. 우리는 여기서 두 개의 섹션을 확인할 수 있습니다:

* `.data`
* `.text`

첫 번째 섹션 - `.data` 에는 프로그램의 초기 상태 데이터가 저장되어 있습니다.(`Hello world` 문자열과 그 길이) 두 번째 섹션 - `.text` 에는 프로그램의 실제 코드가 저장되어 있습니다. 프로그램의 코드를 두 파트로 나누어보죠: 첫 번째 파트는 처음 `syscall` 명령어의 앞 부분, 두 번째 파트는 첫 번째와 두 번째 `syscall` 명령어 사이로 나누어봅시다. 일단 첫번째로, `syscall` 인스트럭션은 일반적으로 코드에서 어떤 일을 할까요? 그건 [64-ia-32-architectures-software-developer-vol-2b-manual](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)에서 읽을 수 있습니다:

```
SYSCALL invokes an OS system-call handler at privilege level 0. It does so by
loading RIP from the IA32_LSTAR MSR (after saving the address of the instruction
following SYSCALL into RCX). (The WRMSR instruction ensures that the
IA32_LSTAR MSR always contain a canonical address.)
...
...
...
SYSCALL loads the CS and SS selectors with values derived from bits 47:32 of the
IA32_STAR MSR. However, the CS and SS descriptor caches are not loaded from the
descriptors (in GDT or LDT) referenced by those selectors.

Instead, the descriptor caches are loaded with fixed values. It is the respon-
sibility of OS software to ensure that the descriptors (in GDT or LDT) referenced
by those selector values correspond to the fixed values loaded into the descriptor
caches; the SYSCALL instruction does not ensure this correspondence.
```

요약하면, `syscall` 인스트럭션은 `MSR_LSTAR` [Model specific register](https://en.wikipedia.org/wiki/Model-specific_register)(Long system target address register)에 저장된 주소로 점프하는 역할을 합니다. 커널은 시스템이 시작할 때 `MSR_LSTAR` 레지스터에 시스템 콜 핸들러 함수의 주소를 쓰는 것 뿐만 아니라, 시스템 콜 핸들러 내부에서 실제로 각 시스템 콜을 핸들링 하기 위한 커스텀 함수를 제공해야 합니다.
여기서 커스텀 함수란 [arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/entry_64.S#L98)에 정의된 `entry_SYSCALL_64`를 뜻합니다. 이 시스템 핸들링 함수의 주소는 커널이 시작하는 도중 [arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/kernel/cpu/common.c#L1335)에서 `MSR_LSTAR` 레지스터에 쓰여집니다.

```C
wrmsrl(MSR_LSTAR, entry_SYSCALL_64);
```

좋아요. `syscall` 인스트럭션이 주어진 시스템 콜의 핸들러를 호출해요. 그런데 실제로 어떤 핸들러를 호출해야 하는지 어떻게 알 수 있을까요? 사실 해당 정보는 범용 [레지스터](https://en.wikipedia.org/wiki/Processor_register)에서 가져옵니다. [시스템 콜 테이블](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl)에서 볼 수 있듯이, 각 시스템 콜은 고유한 번호를 가지고 있습니다. 우리 예시에서 첫번째 시스템 콜은 `write` 시스템 콜이고, 주어진 파일에 데이터를 쓰는 역할을 합니다. 한 번 시스템 콜 테이블에서 `write` 시스템 콜의 위치를 찾아보세요. [write](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl#L10) 시스템 콜이 숫자 `1`에 해당되는 것을 확인하셨을 겁니다. 우리는 이 숫자를 `rax` 레지스터를 통해 넘길 것입니다. 그 다음으로 `write` 시스템 콜을 수행하기 위해 필요한 세 개의 인자(parameter)를 넘기기 위해서는 각각 `%rdi`, `%rsi`, `%rdx` 범용 레지스터를 이용할겁니다. 다음을 확인해보세요:

* `%rdi` : [파일 디스크립터](https://en.wikipedia.org/wiki/File_descriptor) (`1` 은 [stdout](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_.28stdout.29) 을 의미함)
* `%rsi` : string에 대한 포인터
* `%rdx` : 데이터의 크기

흠.. 당신이 제대로 본 게 맞아요. 위 내용은 시스템 콜에 필요한 인자에 대해 설명하고 있어요. 제가 위에서 말했던 것처럼, 시스템 콜은 단지 커널 스페이스의 `C` 함수일 뿐이예요. 위의 예제에서는 첫번째 시스템 콜이 `write` 인 것입니다. 이 시스템 콜은 [fs/read_write.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/read_write.c)소스 코드에 정의가 되어있어요. 그리고 이렇게 생겼죠:

```C
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	...
	...
	...
}
```

다시 말하면 이렇게 생겼죠:

```C
ssize_t write(int fd, const void *buf, size_t nbytes);
```

지금은 `SYSCALL_DEFINE3` 매크로를 보고 너무 걱정하지 마세요. 나중에 다시 돌아올 겁니다.

위 예시의 두번째 파트는 거의 똑같지만, 사실 다른 시스템 콜을 부릅니다. 이 경우에는 [exit](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl#L69) 시스템 콜을 부릅니다. 이 시스템 콜은 딱 하나의 인자만 받습니다:

* `%rdi`: 리턴값(Return value)

그리고 프로그램이 종료되는 방식을 처리하죠. 한 번 위의 예시 프로그램을 [strace](https://en.wikipedia.org/wiki/Strace) 유틸리티로 실행해보면 실제로 시스템 콜이 동작하는 것을 확인할 수 있습니다:

```
$ strace test
execve("./test", ["./test"], [/* 62 vars */]) = 0
write(1, "Hello, world!\n", 14Hello, world!
)         = 14
_exit(0)                                = ?

+++ exited with 0 +++
```

`strace` output의 첫번째 줄에서, [execve](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl#L68) 시스템 콜이 우리의 프로그램을 실행하는 것을 확인할 수 있습니다. 두 번째와 세 번째는 우리가 프로그램에서 사용했던 `write` 와 `exit` 시스템 콜입니다. 위 예시에서 범용 레지스터를 통해 매개 변수를 전달한다는 것을 알아두세요. 레지스터 순서는 우연적인 것이 아니라 [x86-64 콜링 컨벤션](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)에 의해 정의됩니다. 이 컨벤션과 `x86_64` 아키텍쳐의 다른 컨벤션에 관련해서는 바로 뒤의 특별한 문서에서 다루고 있습니다. - [System V Application Binary Interface. PDF](https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-r252.pdf). 일반적으로, 함수의 인자는 레지스터에 저장이 되거나 스택에 push 됩니다. 함수의 처음 6개의 매개 변수에 대해 저장되는 순서는 다음과 같습니다:

* `rdi`
* `rsi`
* `rdx`
* `rcx`
* `r8`
* `r9`

만약 함수가 6개 이상의 인자를 가진다면 남은 인자들은 스택에 저장이 됩니다.

우리는 코드에서 직접 시스템 콜을 사용하지 않습니다. 프로그램이 뭔가를 출력하거나 파일에 접근해 읽기, 쓰기를 원할 때 내부적으로 시스템 콜을 사용합니다.

예를 들어보죠:

```C
#include <stdio.h>

int main(int argc, char **argv)
{
   FILE *fp;
   char buff[255];

   fp = fopen("test.txt", "r");
   fgets(buff, 255, fp);
   printf("%s\n", buff);
   fclose(fp);

   return 0;
}
```

리눅스 커널에는 `fopen`, `fgets`, `printf`, `fclose` 시스템 콜은 없지만, `open`, `read`, `write`, `close` 시스템 콜은 있습니다. 저는 아마 여러분이 `fopen`, `fgets`, `printf`, `fclose` 함수가 `C` [표준 라이브러리](https://en.wikipedia.org/wiki/GNU_C_Library)에 정의되어 있다는 것을 알 것이라고 생각합니다. 사실 이 함수들은 시스템 콜을 위한 wrapper일 뿐입니다. 다시 말하지만, 우리는 코드에서 시스템 콜을 직접 호출하지 않고 표준 라이브러리에 정의된 [wrapper](https://en.wikipedia.org/wiki/Wrapper_function) 함수를 사용합니다. 사실 The main reason of this is simple: a system call must be performed quickly, very quickly. As a system call must be quick, it must be small. The standard library takes responsibility to perform system calls with the correct parameters and makes different checks before it will call the given system call. Let's compile our program with the following command:

```
$ gcc test.c -o test
```

and examine it with the [ltrace](https://en.wikipedia.org/wiki/Ltrace) util:

```
$ ltrace ./test
__libc_start_main([ "./test" ] <unfinished ...>
fopen("test.txt", "r")                                             = 0x602010
fgets("Hello World!\n", 255, 0x602010)                             = 0x7ffd2745e700
puts("Hello World!\n"Hello World!

)                                                                  = 14
fclose(0x602010)                                                   = 0
+++ exited (status 0) +++
```

The `ltrace` util displays a set of userspace calls of a program. The `fopen` function opens the given text file, the `fgets` function reads file content to the `buf` buffer, the `puts` function prints the buffer to `stdout`, and the `fclose` function closes the file given by the file descriptor. And as I already wrote, all of these functions call an appropriate system call. For example, `puts` calls the `write` system call inside, we can see it if we will add `-S` option to the `ltrace` program:

```
write@SYS(1, "Hello World!\n\n", 14) = 14
```

Yes, system calls are ubiquitous. Each program needs to open/write/read files and network connections, allocate memory, and many other things that can be provided only by the kernel. The [proc](https://en.wikipedia.org/wiki/Procfs) file system contains special files in a format: `/proc/${pid}/syscall` that exposes the system call number and argument registers for the system call currently being executed by the process. For example, pid 1 is [systemd](https://en.wikipedia.org/wiki/Systemd) for me:

```
$ sudo cat /proc/1/comm
systemd

$ sudo cat /proc/1/syscall
232 0x4 0x7ffdf82e11b0 0x1f 0xffffffff 0x100 0x7ffdf82e11bf 0x7ffdf82e11a0 0x7f9114681193
```

the system call with number - `232` which is [epoll_wait](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl#L241) system call that waits for an I/O event on an [epoll](https://en.wikipedia.org/wiki/Epoll) file descriptor. Or for example `emacs` editor where I'm writing this part:

```
$ ps ax | grep emacs
2093 ?        Sl     2:40 emacs

$ sudo cat /proc/2093/comm
emacs

$ sudo cat /proc/2093/syscall
270 0xf 0x7fff068a5a90 0x7fff068a5b10 0x0 0x7fff068a59c0 0x7fff068a59d0 0x7fff068a59b0 0x7f777dd8813c
```

the system call with the number `270` which is [sys_pselect6](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl#L279) system call that allows `emacs` to monitor multiple file descriptors.

Now we know a little about system call, what is it and why we need in it. So let's look at the `write` system call that our program used.

Implementation of write system call
--------------------------------------------------------------------------------

Let's look at the implementation of this system call directly in the source code of the Linux kernel. As we already know, the `write` system call is defined in the [fs/read_write.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/read_write.c) source code file and looks like this:

```C
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_write(f.file, buf, count, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	return ret;
}
```

First of all, the `SYSCALL_DEFINE3` macro is defined in the [include/linux/syscalls.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/syscalls.h) header file and expands to the definition of the `sys_name(...)` function. Let's look at this macro:

```C
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)

#define SYSCALL_DEFINEx(x, sname, ...)                \
        SYSCALL_METADATA(sname, x, __VA_ARGS__)       \
        __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
```

As we can see the `SYSCALL_DEFINE3` macro takes `name` parameter which will represent name of a system call and variadic number of parameters. This macro just expands to the `SYSCALL_DEFINEx` macro that takes the number of the parameters the given system call, the `_##name` stub for the future name of the system call (more about tokens concatenation with the `##` you can read in the [documentation](https://gcc.gnu.org/onlinedocs/cpp/Concatenation.html) of [gcc](https://en.wikipedia.org/wiki/GNU_Compiler_Collection)). Next we can see the `SYSCALL_DEFINEx` macro. This macro expands to the two following macros:

* `SYSCALL_METADATA`;
* `__SYSCALL_DEFINEx`.

Implementation of the first macro `SYSCALL_METADATA` depends on the `CONFIG_FTRACE_SYSCALLS` kernel configuration option. As we can understand from the name of this option, it allows to enable tracer to catch the syscall entry and exit events. If this kernel configuration option is enabled, the `SYSCALL_METADATA` macro executes initialization of the `syscall_metadata` structure that defined in the [include/trace/syscall.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/trace/syscall.h) header file and contains different useful fields as name of a system call, number of a system call in the system call [table](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl), number of parameters of a system call, list of parameter types and etc:

```C
#define SYSCALL_METADATA(sname, nb, ...)                             \
	...                                                              \
	...                                                              \
	...                                                              \
    struct syscall_metadata __used                                   \
              __syscall_meta_##sname = {                             \
                    .name           = "sys"#sname,                   \
                    .syscall_nr     = -1,                            \
                    .nb_args        = nb,                            \
                    .types          = nb ? types_##sname : NULL,     \
                    .args           = nb ? args_##sname : NULL,      \
                    .enter_event    = &event_enter_##sname,          \
                    .exit_event     = &event_exit_##sname,           \
                    .enter_fields   = LIST_HEAD_INIT(__syscall_meta_##sname.enter_fields), \
             };                                                                            \

    static struct syscall_metadata __used                           \
              __attribute__((section("__syscalls_metadata")))       \
             *__p_syscall_meta_##sname = &__syscall_meta_##sname;
```

If the `CONFIG_FTRACE_SYSCALLS` kernel option is not enabled during kernel configuration, the `SYSCALL_METADATA` macro expands to an empty string:

```C
#define SYSCALL_METADATA(sname, nb, ...)
```

The second macro `__SYSCALL_DEFINEx` expands to the definition of the five following functions:

```C
#define __SYSCALL_DEFINEx(x, name, ...)                                 \
        asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))       \
                __attribute__((alias(__stringify(SyS##name))));         \
                                                                        \
        static inline long SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__));  \
                                                                        \
        asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__));      \
                                                                        \
        asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__))       \
        {                                                               \
                long ret = SYSC##name(__MAP(x,__SC_CAST,__VA_ARGS__));  \
                __MAP(x,__SC_TEST,__VA_ARGS__);                         \
                __PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));       \
                return ret;                                             \
        }                                                               \
                                                                        \
        static inline long SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__))
```

The first `sys##name` is definition of the syscall handler function with the given name - `sys_system_call_name`. The `__SC_DECL` macro takes the `__VA_ARGS__` and combines call input parameter system type and the parameter name, because the macro definition is unable to determine the parameter types. And the `__MAP` macro applies `__SC_DECL` macro to the `__VA_ARGS__` arguments. The other functions that are generated by the `__SYSCALL_DEFINEx` macro are need to protect from the [CVE-2009-0029](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0029) and we will not dive into details about this here. Ok, as result of the `SYSCALL_DEFINE3` macro, we will have:

```C
asmlinkage long sys_write(unsigned int fd, const char __user * buf, size_t count);
```

Now we know a little about the system call's definition and we can go back to the implementation of the `write` system call. Let's look on the implementation of this system call again:

```C
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos = file_pos_read(f.file);
		ret = vfs_write(f.file, buf, count, &pos);
		if (ret >= 0)
			file_pos_write(f.file, pos);
		fdput_pos(f);
	}

	return ret;
}
```

As we already know and can see from the code, it takes three arguments:

* `fd`    - file descriptor;
* `buf`   - buffer to write;
* `count` - length of buffer to write.

and writes data from a buffer declared by the user to a given device or a file. Note that the second parameter `buf`, defined with the `__user` attribute. The main purpose of this attribute is for checking the Linux kernel code with the [sparse](https://en.wikipedia.org/wiki/Sparse) util. It is defined in the [include/linux/compiler.h](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/linux/compiler.h) header file and depends on the `__CHECKER__` definition in the Linux kernel. That's all about useful meta-information related to our `sys_write` system call, let's try to understand how this system call is implemented. As we can see it starts from the definition of the `f` structure that has `fd` structure type that represents file descriptor in the Linux kernel and we put the result of the call of the `fdget_pos` function. The `fdget_pos` function defined in the same [source](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/read_write.c) code file and just expands the call of the `__to_fd` function:

```C
static inline struct fd fdget_pos(int fd)
{
        return __to_fd(__fdget_pos(fd));
}
```

The main purpose of the `fdget_pos` is to convert the given file descriptor which is just a number to the `fd` structure. Through the long chain of function calls, the `fdget_pos` function gets the file descriptor table of the current process, `current->files`, and tries to find a corresponding file descriptor number there. As we got the `fd` structure for the given file descriptor number, we check it and return if it does not exist. We get the current position in the file with the call of the `file_pos_read` function that just returns `f_pos` field of our file:

```C
static inline loff_t file_pos_read(struct file *file)
{
        return file->f_pos;
}
```

and calls the `vfs_write` function. The `vfs_write` function defined in the [fs/read_write.c](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/fs/read_write.c) source code file and does the work for us - writes given buffer to the given file starting from the given position. We will not dive into details about the `vfs_write` function, because this function is weakly related to the `system call` concept but mostly about [Virtual file system](https://en.wikipedia.org/wiki/Virtual_file_system) concept which we will see in another chapter. After the `vfs_write` has finished its work, we check the result and if it was finished successfully we change the position in the file with the `file_pos_write` function:

```C
if (ret >= 0)
	file_pos_write(f.file, pos);
```

that just updates `f_pos` with the given position in the given file:

```C
static inline void file_pos_write(struct file *file, loff_t pos)
{
        file->f_pos = pos;
}
```

At the end of the our `write` system call handler, we can see the call of the following function:

```C
fdput_pos(f);
```

unlocks the `f_pos_lock` mutex that protects file position during concurrent writes from threads that share file descriptor.

That's all.

We have seen the partial implementation of one system call provided by the Linux kernel. Of course we have missed some parts in the implementation of the `write` system call, because as I mentioned above, we will see only system calls related stuff in this chapter and will not see other stuff related to other subsystems, such as [Virtual file system](https://en.wikipedia.org/wiki/Virtual_file_system).

Conclusion
--------------------------------------------------------------------------------

This concludes the first part covering system call concepts in the Linux kernel. We have covered the theory of system calls so far and in the next part we will continue to dive into this topic, touching Linux kernel code related to system calls.

If you have questions or suggestions, feel free to ping me in twitter [0xAX](https://twitter.com/0xAX), drop me [email](anotherworldofworld@gmail.com) or just create [issue](https://github.com/0xAX/linux-insides/issues/new).

**Please note that English is not my first language and I am really sorry for any inconvenience. If you found any mistakes please send me PR to [linux-insides](https://github.com/0xAX/linux-insides).**

Links
--------------------------------------------------------------------------------

* [system call](https://en.wikipedia.org/wiki/System_call)
* [vdso](https://en.wikipedia.org/wiki/VDSO)
* [vsyscall](https://lwn.net/Articles/446528/)
* [general purpose registers](https://en.wikipedia.org/wiki/Processor_register)
* [socket](https://en.wikipedia.org/wiki/Network_socket)
* [C programming language](https://en.wikipedia.org/wiki/C_%28programming_language%29)
* [x86](https://en.wikipedia.org/wiki/X86)
* [x86_64](https://en.wikipedia.org/wiki/X86-64)
* [x86-64 calling conventions](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)
* [System V Application Binary Interface. PDF](http://www.x86-64.org/documentation/abi.pdf)
* [GCC](https://en.wikipedia.org/wiki/GNU_Compiler_Collection)
* [Intel manual. PDF](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)
* [system call table](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/arch/x86/entry/syscalls/syscall_64.tbl)
* [GCC macro documentation](https://gcc.gnu.org/onlinedocs/cpp/Concatenation.html)
* [file descriptor](https://en.wikipedia.org/wiki/File_descriptor)
* [stdout](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_.28stdout.29)
* [strace](https://en.wikipedia.org/wiki/Strace)
* [standard library](https://en.wikipedia.org/wiki/GNU_C_Library)
* [wrapper functions](https://en.wikipedia.org/wiki/Wrapper_function)
* [ltrace](https://en.wikipedia.org/wiki/Ltrace)
* [sparse](https://en.wikipedia.org/wiki/Sparse)
* [proc file system](https://en.wikipedia.org/wiki/Procfs)
* [Virtual file system](https://en.wikipedia.org/wiki/Virtual_file_system)
* [systemd](https://en.wikipedia.org/wiki/Systemd)
* [epoll](https://en.wikipedia.org/wiki/Epoll)
* [Previous chapter](https://0xax.gitbooks.io/linux-insides/content/Interrupts/index.html)
