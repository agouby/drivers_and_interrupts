#ifndef STROKE_H
#define STROKE_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/seq_file.h>


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

int my_open(struct inode *toto, struct file *tata);
ssize_t my_read(struct file *f, char __user *buf, size_t size, loff_t *p);

#endif
