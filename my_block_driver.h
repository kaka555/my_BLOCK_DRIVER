#ifndef _MY_BLOCK_DRIVER_H
#define _MY_BLOCK_DRIVER_H

#define DEBUG_KAKA

#include <linux/rbtree.h>
#include <linux/blkdev.h>

#define PHY_SIZE (1*1024*1024)
#define BLOCK_DEV_NAME "kaka_disk"
#define SECTOR_SHIFT 9
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#define KA_DISK_ORDER 1 // how many pages we allocate each time
#define KA_BLOCK_SIZE (PAGE_SIZE << (KA_DISK_ORDER - 1))
#define SECTOR_MASK ((1 << (KA_DISK_ORDER + PAGE_SHIFT - SECTOR_SHIFT - 1)) - 1)

struct page;
struct kaka_disk
{
	phys_addr_t addr;
	unsigned long size;
	struct gendisk *kaka_disk;
	struct rb_root disk_space_tree;
};

struct my_block_driver_space
{
	sector_t sector;
	struct page *page_ptr;
	struct rb_node node;
};

struct my_block_driver_space *find_disk_sector_space(sector_t sector, struct kaka_disk *kaka_disk_ptr);
int insert_into_disk_space(struct my_block_driver_space *my_block_driver_space_ptr, struct kaka_disk *kaka_disk_ptr);
struct my_block_driver_space *alloc_driver_space(sector_t sector);
void destory_one_block_driver_space(struct my_block_driver_space *my_block_driver_space_ptr);
void destroy_block_driver_space(struct kaka_disk *kaka_disk_ptr);
int do_data_process(struct kaka_disk *kaka_disk_ptr, struct bio_vec *bio_bvec, int rw, sector_t sector);

#endif