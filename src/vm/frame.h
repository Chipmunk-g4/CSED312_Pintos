#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"

void lru_list_init (void);
void insert_page_lru (struct page* page);
void delete_page_lru (struct page* page);

#endif