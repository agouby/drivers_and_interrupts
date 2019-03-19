#ifndef STROKE_H
#define STROKE_H

struct stroke_s {
	unsigned char value;
	unsigned char state;
	struct list_head list;
};

#endif
