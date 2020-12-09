#ifndef VM_PAGE_H
#define VM_PAGE_H

void swap_init(void);

void swap_in(size_t index, void *frame);
size_t swap_out(void *frame);

#endif