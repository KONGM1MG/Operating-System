#include <list.h>
#include <sync.h>
#include <proc.h>
#include <sched.h>
#include <assert.h>

void
wakeup_proc(struct proc_struct *proc) {
    assert(proc->state != PROC_ZOMBIE && proc->state != PROC_RUNNABLE);
    proc->state = PROC_RUNNABLE;
}

void
schedule(void) {
    bool intr_flag;
    list_entry_t *le, *last;
    struct proc_struct *next = NULL;
    local_intr_save(intr_flag);
    {
        current->need_resched = 0;  // 当前进程不需要调度
        last = (current == idleproc) ? &proc_list : &(current->list_link);
        le = last;
        // 在 proc_list 队列中查找下一个处于“就绪”态的线程或进程 next；
        do {
            if ((le = list_next(le)) != &proc_list) {
                next = le2proc(le, list_link);
                if (next->state == PROC_RUNNABLE) {
                    break;
                }
            }
        } while (le != last);
        if (next == NULL || next->state != PROC_RUNNABLE) {
            next = idleproc;
        }
        next->runs ++;
        if (next != current) {
            // 找到这样的进程后，就调用 proc_run 函数，保存当前进程 current 的执行现场（进程上下文），
            // 恢复新进程的执行现场，完成进程切换。
            proc_run(next);
        }
    }
    local_intr_restore(intr_flag);
}

