#ifndef STROKE_H
#define STROKE_H

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

#define IS_PRESSED(x) (x ? "RELEASED" : "PRESSED")
#define IS_VALID(x) (x < keytable_len ? keytable[x].name : "!UNKNOWN!")
#define IS_PRINT_CMD(x) (x == 0x1C || x == 0x0F || x == 0x39)

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

extern struct keycode_s keytable[];
extern int keytable_len;

#define COUNT_OF(array) (sizeof(array) / sizeof(*array))

void irq_keylogger(unsigned long data);

#endif
