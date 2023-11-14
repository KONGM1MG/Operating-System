#include <proc.h>
#include <kmalloc.h>
#include <string.h>
#include <sync.h>
#include <pmm.h>
#include <error.h>
#include <sched.h>
#include <elf.h>
#include <vmm.h>
#include <trap.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* ------------- process/thread mechanism design&implementation -------------
(an simplified Linux process/thread mechanism )
introduction:
  ucore implements a simple process/thread mechanism. process contains the independent memory sapce, at least one threads
for execution, the kernel data(for management), processor state (for context switch), files(in lab6), etc. ucore needs to
manage all these details efficiently. In ucore, a thread is just a special kind of process(share process's memory).
------------------------------
process state       :     meaning               -- reason
    PROC_UNINIT     :   uninitialized           -- alloc_proc
    PROC_SLEEPING   :   sleeping                -- try_free_pages, do_wait, do_sleep
    PROC_RUNNABLE   :   runnable(maybe running) -- proc_init, wakeup_proc, 
    PROC_ZOMBIE     :   almost dead             -- do_exit

-----------------------------
process state changing:
                                            
  alloc_proc                                 RUNNING
      +                                   +--<----<--+
      +                                   + proc_run +
      V                                   +-->---->--+ 
PROC_UNINIT -- proc_init/wakeup_proc --> PROC_RUNNABLE -- try_free_pages/do_wait/do_sleep --> PROC_SLEEPING --
                                           A      +                                                           +
                                           |      +--- do_exit --> PROC_ZOMBIE                                +
                                           +                                                                  + 
                                           -----------------------wakeup_proc----------------------------------
-----------------------------
process relations
parent:           proc->parent  (proc is children)
children:         proc->cptr    (proc is parent)
older sibling:    proc->optr    (proc is younger sibling)
younger sibling:  proc->yptr    (proc is older sibling)
-----------------------------
related syscall for process:
SYS_exit        : process exit,                           -->do_exit
SYS_fork        : create child process, dup mm            -->do_fork-->wakeup_proc
SYS_wait        : wait process                            -->do_wait
SYS_exec        : after fork, process execute a program   -->load a program and refresh the mm
SYS_clone       : create child thread                     -->do_fork-->wakeup_proc
SYS_yield       : process flag itself need resecheduling, -- proc->need_sched=1, then scheduler will rescheule this process
SYS_sleep       : process sleep                           -->do_sleep 
SYS_kill        : kill process                            -->do_kill-->proc->flags |= PF_EXITING
                                                                 -->wakeup_proc-->do_wait-->do_exit   
SYS_getpid      : get the process's pid

*/

// the process set's list
list_entry_t proc_list; // 所有进程控制块的双向线性列表，proc_struct中的成员变量list_link将链接入这个链表中。


#define HASH_SHIFT          10            // 哈希表位移
#define HASH_LIST_SIZE      (1 << HASH_SHIFT)   // 哈希表大小
#define pid_hashfn(x)       (hash32(x, HASH_SHIFT)) // 进程控制块哈希函数

// has list for process set based on pid
static list_entry_t hash_list[HASH_LIST_SIZE];  // 所有进程控制块的哈希表，proc_struct 中的成员变量 hash_link
                                                // 将基于 pid 链接入这个哈希表中。

// idle proc
struct proc_struct *idleproc = NULL;    // 第0个内核进程
// init proc
struct proc_struct *initproc = NULL;    // 本实验中，指向一个内核线程。本实验以后，此指针将指向第一个用户态进程。
// current proc
struct proc_struct *current = NULL;     // 当前占用 CPU 且处于“运行”状态进程控制块指针。通常这个变量是只读的，只有在进程切换的时候才进行修改，
                                        // 并且整个切换和修改过程需要保证操作的原子性，目前至少需要屏蔽中断。可以参考switch_to的实现。


static int nr_process = 0;  // 当前进程数目

void kernel_thread_entry(void);
void forkrets(struct trapframe *tf);
void switch_to(struct context *from, struct context *to);

// alloc_proc - alloc a proc_struct and init all fields of proc_struct 翻译：建立进程控制块
static struct proc_struct *
alloc_proc(void) {
    struct proc_struct *proc = kmalloc(sizeof(struct proc_struct));
    if (proc != NULL) {
    //LAB4:EXERCISE1 YOUR CODE
    /*
     * below fields in proc_struct need to be initialized
     *       enum proc_state state;                      // Process state
     *       int pid;                                    // Process ID
     *       int runs;                                   // the running times of Proces
     *       uintptr_t kstack;                           // Process kernel stack
     *       volatile bool need_resched;                 // bool value: need to be rescheduled to release CPU?
     *       struct proc_struct *parent;                 // the parent process
     *       struct mm_struct *mm;                       // Process's memory management field
     *       struct context context;                     // Switch here to run process
     *       struct trapframe *tf;                       // Trap frame for current interrupt
     *       uintptr_t cr3;                              // CR3 register: the base addr of Page Directroy Table(PDT)
     *       uint32_t flags;                             // Process flag
     *       char name[PROC_NAME_LEN + 1];               // Process name
     */
    proc->state = PROC_UNINIT;  // 设置进程状态为未初始化
    proc->pid = -1; // 进程 ID
    proc->runs = 0; // 进程运行次数
    proc->kstack = 0;   // 进程内核栈
    proc->need_resched = 0; // 是否需要重新调度
    proc->parent = NULL;    // 父进程
    proc->mm = NULL;    // 进程所用的虚拟内存
    memset(&(proc->context), 0, sizeof(struct context)); // 进程的上下文
    proc->tf = NULL; // 中断帧指针
    proc->cr3 = boot_cr3; // 页目录表地址 设为 内核页目录表基址
    proc->flags = 0; // 标志位
    memset(&(proc->name), 0, PROC_NAME_LEN); // 进程名
    }
    return proc;
}

// set_proc_name - set the name of proc
char *
set_proc_name(struct proc_struct *proc, const char *name) {
    memset(proc->name, 0, sizeof(proc->name));
    return memcpy(proc->name, name, PROC_NAME_LEN);
}

// get_proc_name - get the name of proc
char *
get_proc_name(struct proc_struct *proc) {
    static char name[PROC_NAME_LEN + 1];
    memset(name, 0, sizeof(name));
    return memcpy(name, proc->name, PROC_NAME_LEN);
}

// get_pid - alloc a unique pid for process
// 通过递增last_pid并遍历进程链表来查找未被使用的ID。函数保证了分配的ID在有效范围内（1到MAX_PID - 1）。
static int
get_pid(void) {
    static_assert(MAX_PID > MAX_PROCESS);   // 静态检查
    struct proc_struct *proc;
    list_entry_t *list = &proc_list, *le;
    static int next_safe = MAX_PID, last_pid = MAX_PID; // next_safe 表示下一个安全的进程 ID，last_pid 表示最后一个进程 ID
    if (++ last_pid >= MAX_PID) {   // 如果 last_pid+1 大于等于最大进程 ID，那么将 last_pid 设为 1
        last_pid = 1;
        goto inside;
    }
    if (last_pid >= next_safe) {
    inside: // 如果 last_pid 大于等于 next_safe，那么需要重新遍历进程控制块链表，找到一个没有被占用的进程 ID
        next_safe = MAX_PID;
    repeat: // 重新遍历进程控制块链表
        le = list;
        while ((le = list_next(le)) != list) {
            proc = le2proc(le, list_link);  // 获取进程控制块
            if (proc->pid == last_pid) {    // 如果进程控制块的进程 ID 等于 last_pid
                if (++ last_pid >= next_safe) { // 如果 last_pid 大于等于 next_safe
                    if (last_pid >= MAX_PID) {  // 如果 last_pid 大于等于最大进程 ID，那么将 last_pid 设为 1
                        last_pid = 1;
                    }
                    next_safe = MAX_PID;    // 将 next_safe 设为最大进程 ID
                    goto repeat;    // 重新遍历进程控制块链表
                }
            }
            else if (proc->pid > last_pid && next_safe > proc->pid) {   // 如果进程控制块的进程 ID 大于 last_pid 且小于 next_safe
                next_safe = proc->pid;  // 将 next_safe 设为进程控制块的进程 ID
            }
        }
    }
    return last_pid;
}

// proc_run - make process "proc" running on cpu
// NOTE: before call switch_to, should load  base addr of "proc"'s new PDT
void
proc_run(struct proc_struct *proc) {
    if (proc != current) {
        // LAB4:EXERCISE3 YOUR CODE
        /*
        * Some Useful MACROs, Functions and DEFINEs, you can use them in below implementation.
        * MACROs or Functions:
        *   local_intr_save():        Disable interrupts
        *   local_intr_restore():     Enable Interrupts
        *   lcr3():                   Modify the value of CR3 register
        *   switch_to():              Context switching between two processes
        */
        bool intr_flag;
        struct proc_struct *prev = current, *next = proc;
        local_intr_save(intr_flag); // 关闭中断
        {
            current = proc; // 将当前进程换为 要切换到的进程
            // 设置任务状态段tss中的特权级0下的 esp0 指针为 next 内核线程 的内核栈的栈顶
            // load_esp0(next->kstack + KSTACKSIZE);
            lcr3(next->cr3); // 重新加载 cr3 寄存器(页目录表基址) 进行进程间的页表切换
            switch_to(&(prev->context), &(next->context)); // 调用 switch_to 进行上下文的保存与切换
        }
        local_intr_restore(intr_flag);
    }
}

// forkret -- the first kernel entry point of a new thread/process
// NOTE: the addr of forkret is setted in copy_thread function
//       after switch_to, the current proc will execute here.
static void
forkret(void) {
    forkrets(current->tf);
}

// hash_proc - add proc into proc hash_list
static void
hash_proc(struct proc_struct *proc) {
    list_add(hash_list + pid_hashfn(proc->pid), &(proc->hash_link));
}

// find_proc - find proc frome proc hash_list according to pid
struct proc_struct *
find_proc(int pid) {
    if (0 < pid && pid < MAX_PID) {
        list_entry_t *list = hash_list + pid_hashfn(pid), *le = list;
        while ((le = list_next(le)) != list) {
            struct proc_struct *proc = le2proc(le, hash_link);
            if (proc->pid == pid) {
                return proc;
            }
        }
    }
    return NULL;
}

// kernel_thread - create a kernel thread using "fn" function
// NOTE: the contents of temp trapframe tf will be copied to 
//       proc->tf in do_fork-->copy_thread function
// 创建内核线程，kernel_thread 函数采用了局部变量 tf 来放置保存内核线程的临时中断帧，并把中断帧的指针传递给
// do_fork 函数，而 do_fork 函数会调用 copy_thread 函数来在新创建的进程内核栈上专门给进程的中断帧分配
// 一块空间。
int
kernel_thread(int (*fn)(void *), void *arg, uint32_t clone_flags) {
    // 对trameframe， 也就是我们程序的一些上下文进行一些初始化
    struct trapframe tf;
    memset(&tf, 0, sizeof(struct trapframe));
    // 设置内核线程的参数和函数指针
    tf.gpr.s0 = (uintptr_t)fn;  // s0寄存器存储函数指针
    tf.gpr.s1 = (uintptr_t)arg; // s1寄存器存储函数参数
    // 设置trapframe的status寄存器
    // SSTATUS_SPP: Previous Privilege mode, 1=Supervisor, 0=User 设置为supervisor，因为这是一个内核线程
    // SSTATUS_SPIE: Supervisor Previous Interrupt Enable 设置为启用中断，因为这是一个内核线程
    // SSTATUS_SIE: Supervisor Interrupt Enable 设置为0，禁止中断，不希望线程被中断
    tf.status = (read_csr(sstatus) | SSTATUS_SPP | SSTATUS_SPIE) & ~SSTATUS_SIE;
    // 将入口点epc设置为kernel_thread_entry，实际上是将pc指向它（*trapentry.S）
    tf.epc = (uintptr_t)kernel_thread_entry;
    // 使用do_fork函数创建内核线程，这样才真正用设置的tf创建新线程
    return do_fork(clone_flags | CLONE_VM, 0, &tf);
}

// setup_kstack - alloc pages with size KSTACKPAGE as process kernel stack
static int
setup_kstack(struct proc_struct *proc) {
    struct Page *page = alloc_pages(KSTACKPAGE);
    if (page != NULL) {
        proc->kstack = (uintptr_t)page2kva(page);
        return 0;
    }
    return -E_NO_MEM;
}

// put_kstack - free the memory space of process kernel stack
static void
put_kstack(struct proc_struct *proc) {
    free_pages(kva2page((void *)(proc->kstack)), KSTACKPAGE);
}

// copy_mm - process "proc" duplicate OR share process "current"'s mm according clone_flags
//         - if clone_flags & CLONE_VM, then "share" ; else "duplicate"
static int
copy_mm(uint32_t clone_flags, struct proc_struct *proc) {
    assert(current->mm == NULL);
    /* do nothing in this project */
    return 0;
}

// copy_thread - setup the trapframe on the  process's kernel stack top and
//             - setup the kernel entry point and stack of process
static void
copy_thread(struct proc_struct *proc, uintptr_t esp, struct trapframe *tf) {
    // 先在上面分配的内核栈上分配出一片空间来保存trapframe
    proc->tf = (struct trapframe *)(proc->kstack + KSTACKSIZE - sizeof(struct trapframe));
    *(proc->tf) = *tf;

    // Set a0 to 0 so a child process knows it's just forked
    // trapframe中的a0寄存器（返回值）设置为0，说明这个进程是一个子进程
    proc->tf->gpr.a0 = 0;
    proc->tf->gpr.sp = (esp == 0) ? (uintptr_t)proc->tf : esp;
    // 们将上下文中的 ra 设置为了forkret 函数的入口，并且把 trapframe 放在上下文的栈顶
    proc->context.ra = (uintptr_t)forkret;
    proc->context.sp = (uintptr_t)(proc->tf);
}

/* do_fork -     parent process for a new child process
 * @clone_flags: used to guide how to clone the child process
 * @stack:       the parent's user stack pointer. if stack==0, It means to fork a kernel thread.
 * @tf:          the trapframe info, which will be copied to child process's proc->tf
 */
int
do_fork(uint32_t clone_flags, uintptr_t stack, struct trapframe *tf) {
    int ret = -E_NO_FREE_PROC;
    struct proc_struct *proc;
    if (nr_process >= MAX_PROCESS) {
        goto fork_out;
    }
    ret = -E_NO_MEM;
    //LAB4:EXERCISE2 YOUR CODE
    /*
     * Some Useful MACROs, Functions and DEFINEs, you can use them in below implementation.
     * MACROs or Functions:
     *   alloc_proc:   create a proc struct and init fields (lab4:exercise1)
     *   setup_kstack: alloc pages with size KSTACKPAGE as process kernel stack
     *   copy_mm:      process "proc" duplicate OR share process "current"'s mm according clone_flags
     *                 if clone_flags & CLONE_VM, then "share" ; else "duplicate"
     *   copy_thread:  setup the trapframe on the  process's kernel stack top and
     *                 setup the kernel entry point and stack of process
     *   hash_proc:    add proc into proc hash_list
     *   get_pid:      alloc a unique pid for process
     *   wakeup_proc:  set proc->state = PROC_RUNNABLE
     * VARIABLES:
     *   proc_list:    the process set's list
     *   nr_process:   the number of process set
     */

    //    1. call alloc_proc to allocate a proc_struct
    //    2. call setup_kstack to allocate a kernel stack for child process
    //    3. call copy_mm to dup OR share mm according clone_flag
    //    4. call copy_thread to setup tf & context in proc_struct
    //    5. insert proc_struct into hash_list && proc_list
    //    6. call wakeup_proc to make the new child process RUNNABLE
    //    7. set ret vaule using child proc's pid

    if ((proc = alloc_proc()) == NULL)  // 分配并初始化进程控制块
    	goto fork_out;    
    if (setup_kstack(proc) != 0)    // 分配并初始化内核栈
    	goto bad_fork_cleanup_proc;
    if (copy_mm(clone_flags, proc) != 0)    // 根据 clone_flags 决定是复制还是共享内存管理系统（copy_mm 函数）
    	goto bad_fork_cleanup_kstack;    
    copy_thread(proc, stack, tf);   // 复制父进程的中断帧和上下文，设置子进程的中断帧和上下文
    proc->pid = get_pid();  // 分配进程 ID
    nr_process++;   // 进程数加一
    hash_proc(proc);    // 将进程控制块链接到哈希表中
    list_add_before(&proc_list, &proc->list_link);  // 将进程控制块链接到进程控制块链表中
    wakeup_proc(proc);  // 将进程状态设置为 PROC_RUNNABLE，表示进程可以运行
    ret = proc->pid;    // 返回子进程的进程 ID
    
    // 如果上述前 3 步执行没有成功，则需要做对应的出错处理，把相关已经占有的内存释
    // 放掉。copy_mm 函数目前只是把 current->mm 设置为 NULL，这是由于目前在实验四中只能创建内核线程，
    // proc->mm 描述的是进程用户态空间的情况，所以目前 mm 还用不上。

fork_out:
    return ret;

bad_fork_cleanup_kstack:
    put_kstack(proc);
bad_fork_cleanup_proc:
    kfree(proc);
    goto fork_out;
}

// do_exit - called by sys_exit
//   1. call exit_mmap & put_pgdir & mm_destroy to free the almost all memory space of process
//   2. set process' state as PROC_ZOMBIE, then call wakeup_proc(parent) to ask parent reclaim itself.
//   3. call scheduler to switch to other process
int
do_exit(int error_code) {
    panic("process exit!!.\n");
}

// init_main - the second kernel thread used to create user_main kernel threads
static int
init_main(void *arg) {
    cprintf("this initproc, pid = %d, name = \"%s\"\n", current->pid, get_proc_name(current));
    cprintf("To U: \"%s\".\n", (const char *)arg);
    cprintf("To U: \"en.., Bye, Bye. :)\"\n");
    return 0;
}

// proc_init - set up the first kernel thread idleproc "idle" by itself and 
//           - create the second kernel thread init_main 翻译：设置第一个内核线程idleproc“idle”本身并创建第二个内核线程init_main
void
proc_init(void) {
    int i;

    list_init(&proc_list);  // 进程控制块链表初始化
    for (i = 0; i < HASH_LIST_SIZE; i ++) {
        list_init(hash_list + i);
    }
    // 分配idleproc
    if ((idleproc = alloc_proc()) == NULL) {
        panic("cannot alloc idleproc.\n");
    }

    // check the proc structure 检查进程结构
    int *context_mem = (int*) kmalloc(sizeof(struct context));
    memset(context_mem, 0, sizeof(struct context));
    int context_init_flag = memcmp(&(idleproc->context), context_mem, sizeof(struct context));

    int *proc_name_mem = (int*) kmalloc(PROC_NAME_LEN);
    memset(proc_name_mem, 0, PROC_NAME_LEN);
    int proc_name_flag = memcmp(&(idleproc->name), proc_name_mem, PROC_NAME_LEN);

    if(idleproc->cr3 == boot_cr3 && idleproc->tf == NULL && !context_init_flag
        && idleproc->state == PROC_UNINIT && idleproc->pid == -1 && idleproc->runs == 0
        && idleproc->kstack == 0 && idleproc->need_resched == 0 && idleproc->parent == NULL
        && idleproc->mm == NULL && idleproc->flags == 0 && !proc_name_flag
    ){
        cprintf("alloc_proc() correct!\n");

    }
    
    idleproc->pid = 0;  // idleproc的合法的pid为0
    idleproc->state = PROC_RUNNABLE;    // 设置进程状态为可运行
    idleproc->kstack = (uintptr_t)bootstack;    // 设置内核栈起始地址，以后的其他线程的内核栈需要分配获得
    idleproc->need_resched = 1; // 设置需要重新调度，希望CPU应该做更有用的工作，而不是运行idleproc
    set_proc_name(idleproc, "idle");
    nr_process ++;

    current = idleproc;

    int pid = kernel_thread(init_main, "Hello world!!", 0);
    if (pid <= 0) {
        panic("create init_main failed.\n");
    }

    initproc = find_proc(pid);
    set_proc_name(initproc, "init");

    assert(idleproc != NULL && idleproc->pid == 0);
    assert(initproc != NULL && initproc->pid == 1);
}

// cpu_idle - at the end of kern_init, the first kernel thread idleproc will do below works
// idle线程最终会执行cpu_idle函数，该函数的作用是让CPU空闲下来，等待中断的到来。
void
cpu_idle(void) {
    while (1) { // 判断当前内核线程 idleproc 的 need_resched 是否不为 0
        if (current->need_resched) {
            schedule(); //调用schedule函数找其他处于“就绪”态的进程执行。
        }
    }
}

