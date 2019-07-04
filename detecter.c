#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <asm/asm-offsets.h>
#include <linux/fs.h>

#define IA32_LSTAR  0xc0000082

/*
ubuntu14.04 64位，内核一些关键字段的数据
ffffffff81000000 T _text
ffffffff81831f81 T _etext
ffffffff81e00000 D _sdata
ffffffff81f4f700 D _edata
ffffffff81a00000 R __start_rodata
ffffffff81dee000 R __end_rodata
ffffffff820cf000 B __bss_start
ffffffff82218000 B __bss_stop
ffffffff81f51000 D __init_begin
ffffffff820c6000 R __init_end
ffffffff81f6a000 T _sinittext
ffffffff81fd30bb T _einittext
*/

struct {
	unsigned short size;
	unsigned long addr;
}__attribute__((packed)) idtr;

struct {
	unsigned short offset_1;  /*offset bits 0..15*/
	unsigned short selector;  /*a code segment selector in GDT or LDT*/
	unsigned char zero1;       /*unused, set to 0*/
	unsigned char type_attr;  /*type and attributes*/
	unsigned short offset_2;  /*offset bits 16..31*/
	/*
	和32位相比，就是多了一个高32位地址，和对齐补0
	*/
	unsigned int offset_3;
	unsigned int zero2;
}__attribute__((packed)) syscall_idt;

int det_idt32(void){
	int i;
	unsigned char* ptr;
	unsigned long* addr;
	unsigned long* syscall = NULL;
	//unsigned char idtr[16];
	//unsigned long base;
	//struct idt_descriptor desc;
	//unsigned long* idt = (unsigned long *)kallsyms_lookup_name("idt_table");
	//printk("[det]:%p\n",idt);
	asm ("sidt %0" : "=m" (idtr));
	//printk("[det]:%lx\n", idtr.addr);
	//printk("[det]:%lx\n", (unsigned long)kallsyms_lookup_name("idt_table"));
	memcpy(&syscall_idt, (void*)idtr.addr+sizeof(syscall_idt)*0x80, sizeof(syscall_idt));
	addr = (unsigned long *)((unsigned long)syscall_idt.offset_3<<32 | (unsigned long)syscall_idt.offset_2<<16 | (unsigned long)syscall_idt.offset_1);
	//printk("[det]:%p\n", addr);
	if(addr<(unsigned long*)kallsyms_lookup_name("_text") || addr>(unsigned long*)kallsyms_lookup_name("__bss_stop"))
		printk("[det]: idt32 wrong\n");
	for(ptr=(unsigned char*)addr,i=0; i<500; i++) {
		//printk("deed");
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5){
			//printk("%ld\n",(unsigned long)(0xffffffff00000000 | *((unsigned int*)(ptr+3))));
			syscall = (unsigned long*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
			break;
		}
		ptr++;
	}
	//printk("%p\n",syscall);
	if(syscall<(unsigned long*)kallsyms_lookup_name("_text") || syscall>(unsigned long*)kallsyms_lookup_name("__bss_stop"))
		printk("[det]: idt32 wrong 2\n");
	return 0;
}

int det_idt(void){
	unsigned long *system_call;
	unsigned char *ptr;
	int i, low, high;
	unsigned long* syscall = NULL;
	asm("rdmsr" : "=a" (low), "=d" (high) : "c" (IA32_LSTAR));
	system_call = (void*)(((long)high<<32) | low);
	//printk("[det]:%p\n",system_call);
	//printk("[det]:%lx\n", (unsigned long)kallsyms_lookup_name("idt_table"));
	if(system_call<(unsigned long*)kallsyms_lookup_name("_text") || system_call>(unsigned long*)kallsyms_lookup_name("__bss_stop"))
		printk("[det]: idt wrong\n");
	for (ptr=(unsigned char*)system_call, i=0; i<500; i++) {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5){
			//printk("[det]:hello\n");
			//printk("[det]:%p\n",(void*)(0xffffffff00000000 | *((unsigned int*)(ptr+3))));
			syscall = (unsigned long*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
		}
		ptr++;
	}
	if(syscall<(unsigned long*)kallsyms_lookup_name("_text") || syscall>(unsigned long*)kallsyms_lookup_name("__bss_stop"))
		printk("[det]: idt wrong 2\n");
	return 0;
}

int det_syscall(void){
	int i;
	unsigned long _text;
	unsigned long __bss_stop;
	unsigned long * syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	_text = (unsigned long)kallsyms_lookup_name("_text");
	__bss_stop = (unsigned long)kallsyms_lookup_name("__bss_stop");
	for (i = 0; i < NR_syscalls; i++){
		//printk("[det]:enter loop");
		if(syscall_table[i]<_text || syscall_table[i]>__bss_stop)
			printk("[det]:syscall wrong");
	}
	return 0;
}

int det_file(void){
	struct file *filp;
	struct file_operations *f_op;
	unsigned long* _text;
	unsigned long* __bss_stop;
	_text = (unsigned long*)kallsyms_lookup_name("_text");
	__bss_stop = (unsigned long*)kallsyms_lookup_name("__bss_stop");
	filp = filp_open("/", O_RDONLY, 0);
	f_op = (struct file_operations *)filp->f_op;
	//printk("[det]:%p\n",(unsigned long*)(f_op->iterate));
	if((unsigned long*)(f_op->iterate)<_text || (unsigned long*)(f_op->iterate)>__bss_stop){
		printk("[det]:file wrong\n");
	}
	return 0;
}

static int det_init(void)
{
	printk("det_init\n");
	det_idt32();
	det_idt();
	det_syscall();
	det_file();
	return 0;
}

static void det_exit(void)
{
	printk("det_exit\n");
}

MODULE_LICENSE("GPL");
module_init(det_init);
module_exit(det_exit);
