#include "vm/page.h"
#include "vm/swap.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"

struct lock swap_lock;
struct block * swap_block;
struct bitmap * swap_map;

#define BLOCK_SECTOR 8

void swap_init(void) {
  // initialize lock
  lock_init(&swap_lock);

  // create block for swap
  swap_block = block_get_role(BLOCK_SWAP);

  // create bitmap for swap
  swap_map = bitmap_create(block_size(swap_block) / BLOCK_SECTOR);
  // initialize bitmap value as 0
  bitmap_set_all(swap_map, 0);
}

void swap_in(size_t index, void *frame) {
  lock_acquire(&swap_lock);

//  before read data from block, check index is valid. (== is occupied)
  if(bitmap_test(swap_map, index) == 0) return;

  for(int i = 0; i < BLOCK_SECTOR; i++)
    block_read(swap_block, index * BLOCK_SECTOR + i, frame + i * BLOCK_SECTOR_SIZE);

//  after read from block, set bit 1 to 0 (discard bit)
  bitmap_flip(swap_map, index);

  lock_release(&swap_lock);
}

size_t swap_out(void *frame) {
  lock_acquire(&swap_lock);

  int index = bitmap_scan_and_flip(swap_map, 0, 1, 0);

  for(int i = 0; i < BLOCK_SECTOR; i++)
    block_write(swap_block, index * BLOCK_SECTOR_SIZE + i, frame + i * BLOCK_SECTOR_SIZE);

  lock_release(&swap_lock);
  return 0;
}