#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"

struct list lru_list;
struct lock lru_list_lock;
struct list_elem * lru_clock;

void lru_list_init (void);
void insert_page_lru (struct page* page);
void delete_page_lru (struct page* page);
struct list_elem *get_next_lru_clock ();

#endif