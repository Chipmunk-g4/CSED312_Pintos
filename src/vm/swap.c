#include "vm/page.h"
#include "vm/swap.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"

#define BLOCK_

struct lock swap_lock;
struct block * swap_block;
struct bitmap * swap_map;

void swap_init(void) {
  // initialize lock
  lock_init(&swap_lock);

  // create block for swap
  swap_block = block_get_role(BLOCK_SWAP);

  // create bitmap for swap
  swap_map = bitmap_create(block_size(swap_block));
  // initialize bitmap value as 0
  bitmap_set_all(swap_map, 0);
}

void swap_in(size_t index, void *frame) {
  lock_acquire(&swap_lock);

  lock_release(&swap_lock);
}

size_t swap_out(void *frame) {
  lock_acquire(&swap_lock);
  lock_release(&swap_lock);
  return 0;
}