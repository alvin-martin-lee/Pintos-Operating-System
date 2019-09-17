#include <stdio.h>
#include "vm/swap.h"

/* Initialises the swap system */
void
swap_init (void)
{
  /* Initialise the swap lock */
  lock_init (&swap_table_lock);

  /* Initialize the swap block */
  swap_table_block = block_get_role (BLOCK_SWAP);

  /* Initialize the swap bitmap */
  block_sector_t swap_block_size = block_size (swap_table_block);
  size_t swap_bitmap_size = swap_block_size / ST_SECTORS;
  swap_table_bitmap = bitmap_create (swap_bitmap_size);
  bitmap_set_all (swap_table_bitmap, ST_FREE);
}

/* Reads the contents of the specific swap slot into the given frame */
void
swap_load (int swap_num, void *frame)
{
  lock_acquire (&swap_table_lock);

  /* Ensure that the respective bitmap bit is set as used */
  if (bitmap_test (swap_table_bitmap, swap_num) != ST_USED)
    {
      bitmap_set (swap_table_bitmap, swap_num, ST_USED);
    }

  /* Read page into frame from swap slot */
  for (int i = 0; i < ST_SECTORS; i++)
    {
      block_read (swap_table_block,
                  swap_num * ST_SECTORS + i, frame + BLOCK_SECTOR_SIZE * i);
    }

  lock_release (&swap_table_lock);
}

/* Stores the contents of a given frame in the swap slot if possible */
int
swap_store (void *frame)
{
  lock_acquire (&swap_table_lock);

  size_t start = 0;
  size_t count = 1;
  /* Set the respective bitmap bit to free */
  size_t freed_swap_num = bitmap_scan_and_flip (
      swap_table_bitmap, start, count, ST_FREE);

  if (freed_swap_num == BITMAP_ERROR)
    PANIC("Cannot store additional swap data");

  /* Write each sector into the swap slot */
  for (int i = 0; i < ST_SECTORS; i++)
    {
      block_write (swap_table_block,
                   freed_swap_num * ST_SECTORS + i,
                   frame + BLOCK_SECTOR_SIZE * i);
    }

  lock_release (&swap_table_lock);
  return freed_swap_num;
}