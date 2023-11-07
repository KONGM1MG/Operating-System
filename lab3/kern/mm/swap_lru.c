#include <defs.h>
#include <riscv.h>
#include <stdio.h>
#include <string.h>
#include <swap.h>
#include <swap_lru.h>
#include <list.h>

list_entry_t pra_list_head, *curr_ptr;

static int
_lru_init_mm(struct mm_struct *mm)
{     
     list_init(&pra_list_head);
     mm->sm_priv = &pra_list_head;
    curr_ptr = &pra_list_head;
     return 0;
}

static int
_lru_map_swappable(struct mm_struct *mm, uintptr_t addr, struct Page *page, int swap_in)
{
    list_entry_t *head=(list_entry_t*) mm->sm_priv;
    list_entry_t *entry=&(page->pra_page_link);
    assert(entry != NULL && head != NULL);
    list_add(head, entry);
    //visited为距离上一次访问的访问次数
    page->visited = 0;
    return 0;
}

static int
_lru_swap_out_victim(struct mm_struct *mm, struct Page ** ptr_page, int in_tick)
{
     list_entry_t *head=(list_entry_t*) mm->sm_priv;
         assert(head != NULL);
     assert(in_tick==0);

    list_entry_t *le = head->next;
    uint_t max = 0;
    
    cprintf("\nPage swap out begin\n");
    while (le!=head) {
        struct Page* page = le2page(le,pra_page_link);
        if(page->visited >= max){
            max = page->visited;
            curr_ptr = le;
            struct Page* page2 = le2page(curr_ptr,pra_page_link);
        }
        cprintf("Page:%x,Page.visited:%d\n",page2ppn(page),page->visited);
        le = le->next;
    }
    *ptr_page = le2page(curr_ptr,pra_page_link);
    cprintf("vitim Page:%x,Page.visited:%d\n\n",page2ppn(*ptr_page),(*ptr_page)->visited);
    list_del(curr_ptr);
    return 0;
}


static int
_lru_check_swap(void) {
    cprintf("write Virt Page c in lru_check_swap\n");
    lru_write_memory(0x3000,0x0c);
    assert(pgfault_num==4);
    cprintf("write Virt Page a in lru_check_swap\n");
    lru_write_memory(0x1000,0x0a);
    assert(pgfault_num==4);
    cprintf("write Virt Page d in lru_check_swap\n");
    lru_write_memory(0x4000 ,0x0d);
    assert(pgfault_num==4);
    cprintf("write Virt Page b in lru_check_swap\n");
    lru_write_memory(0x2000 ,0x0b);
    assert(pgfault_num==4);
    cprintf("write Virt Page e in lru_check_swap\n");
    lru_write_memory(0x5000 ,0x0e);
    assert(pgfault_num==5);
    cprintf("write Virt Page b in lru_check_swap\n");
    lru_write_memory(0x2000 ,0x0b);
    assert(pgfault_num==5);
    cprintf("write Virt Page a in lru_check_swap\n");
    lru_write_memory(0x1000 ,0x0a);
    assert(pgfault_num==5);
    cprintf("write Virt Page b in lru_check_swap\n");
    lru_write_memory(0x2000 ,0x0b);
    assert(pgfault_num==5);
    cprintf("write Virt Page c in lru_check_swap\n");
    lru_write_memory(0x3000 ,0x0c);
    assert(pgfault_num==6);
    cprintf("write Virt Page d in lru_check_swap\n");
    lru_write_memory(0x4000 ,0x0d);
    assert(pgfault_num==7);
    cprintf("write Virt Page e in lru_check_swap\n");
    lru_write_memory(0x5000 ,0x0e);
    assert(pgfault_num==8);
    cprintf("write Virt Page a in lru_check_swap\n");
    assert(*(unsigned char *)0x1000 == 0x0a);
    lru_write_memory(0x1000 ,0x0a);
    assert(pgfault_num==9);
    return 0;
}


static int
_lru_init(void)
{
    return 0;
}

static int
_lru_set_unswappable(struct mm_struct *mm, uintptr_t addr)
{
    return 0;
}

static int
_lru_tick_event(struct mm_struct *mm)
{ return 0; }


struct swap_manager swap_manager_lru =
{
     .name            = "lru swap manager",
     .init            = &_lru_init,
     .init_mm         = &_lru_init_mm,
     .tick_event      = &_lru_tick_event,
     .map_swappable   = &_lru_map_swappable,
     .set_unswappable = &_lru_set_unswappable,
     .swap_out_victim = &_lru_swap_out_victim,
     .check_swap      = &_lru_check_swap,
};
