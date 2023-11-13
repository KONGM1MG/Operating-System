.text
.globl kernel_thread_entry
kernel_thread_entry:        # void kernel_thread(void)
	move a0, s1	# a0 = fn 将s1寄存器中的内容移动到a0寄存器中。用于将参数传递给函数。它将fn函数的参数传递给a0。
	jalr s0	# fn()	 通过寄存器间接跳转调用fn函数，s0寄存器中存储了fn函数的地址。在这个调用过程中，fn函数的参数可能通过寄存器s1传递。

	jal do_exit	# do_exit()
