#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/hdreg.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/seq_file.h>

#include "my_block_driver.h"

static struct kaka_disk *kaka_disk_ptr;

#ifdef DEBUG_KAKA
char read_write_buffer[PHY_SIZE];
static unsigned int len;
static int flag = 0;

void pre_read_write(struct bio_vec *bio_vec_ptr, sector_t start_sector)
{
	void *mem;
	if ((bio_vec_ptr->bv_len > PAGE_SIZE) || (flag == 1) || (start_sector >= (PHY_SIZE >> SECTOR_SHIFT)))
	{
		BUG();
	}
	mem = kmap(bio_vec_ptr->bv_page);
	memcpy(read_write_buffer + (start_sector << SECTOR_SHIFT), mem + bio_vec_ptr->bv_offset, bio_vec_ptr->bv_len);
	kunmap(bio_vec_ptr->bv_page);
	len = bio_vec_ptr->bv_len;
	flag = 1;
}

void after_read_write(struct bio_vec *bio_vec_ptr, sector_t start_sector)
{
	void *mem;
	struct my_block_driver_space *my_block_driver_space_ptr;
	unsigned int this_loop_len;
	unsigned int count;
	unsigned int this_offset;
	BUG_ON(flag == 0);
	BUG_ON(len != bio_vec_ptr->bv_len);
	count = 0;
	while (count < len)
	{
		my_block_driver_space_ptr = find_disk_sector_space(start_sector, kaka_disk_ptr);
		BUG_ON(my_block_driver_space_ptr == NULL);
		mem = kmap(my_block_driver_space_ptr->page_ptr);
		this_offset = (unsigned int)(count + (start_sector << SECTOR_SHIFT)) & (KA_BLOCK_SIZE - 1);
		BUG_ON(this_offset & (SECTOR_SIZE - 1));
		this_loop_len = min((unsigned int)KA_BLOCK_SIZE - this_offset, len - count);
		BUG_ON(0 != memcmp(read_write_buffer + (start_sector << SECTOR_SHIFT), mem + ((start_sector & SECTOR_MASK) << SECTOR_SHIFT), this_loop_len));
		kunmap(my_block_driver_space_ptr->page_ptr);
		count += this_loop_len;
		start_sector += (this_loop_len >> SECTOR_SHIFT);
	}
	BUG_ON(count != len);
	len = 0;
	flag = 0;
}
#endif

static unsigned long long total_bytes = PHY_SIZE;
static int kaka_disk_major;
struct block_device_operations kaka_blkdev_fops = {
	.owner = THIS_MODULE,
};

static blk_qc_t kaka_blkdev_make_request(struct request_queue *q, struct bio *bio)
{
	struct bio_vec bio_bvec;
	struct bvec_iter iter;
	int rw;
	int ret;
	sector_t sector;
	unsigned long sector_addr;
	int dir = -1;
	sector = bio->bi_iter.bi_sector;
	rw = bio_rw(bio);
	switch (rw)
	{
	case READ:
	case READA:
		dir = 0;
		break;
	case WRITE:
		dir = 1;
		break;
	default:
		pr_err("error rw!!!\n");
		bio->bi_error = -EINVAL;
		goto error_bio;
	}
	sector_addr = sector << SECTOR_SHIFT;
	if ((sector_addr + bio->bi_iter.bi_size) > total_bytes)
	{
		bio->bi_error = -ERANGE;
		goto error_bio;
	}
	//now everything are good
	bio_for_each_segment(bio_bvec, bio, iter)
	{
#ifdef DEBUG_KAKA
		if (dir) //write
			pre_read_write(&bio_bvec, sector);
#endif
		ret = do_data_process(kaka_disk_ptr, &bio_bvec, dir, sector);
		if (ret < 0)
		{
			bio->bi_error = ret;
			goto error_bio;
		}
#ifdef DEBUG_KAKA
		if (dir) //write
			after_read_write(&bio_bvec, sector);
#endif
	}
error_bio:
	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static int __init kakadisk_init(void)
{
	int ret;
	struct request_queue *request_queue_ptr;
	kaka_disk_major = register_blkdev(0, BLOCK_DEV_NAME);
	if (kaka_disk_major < 0)
	{
		ret = kaka_disk_major;
		goto out_register_blkdev;
	}
	kaka_disk_ptr = kmalloc(sizeof(struct kaka_disk), GFP_KERNEL);
	if (kaka_disk_ptr == NULL)
	{
		ret = -ENOMEM;
		goto out_kaka_disk_ptr;
	}
	request_queue_ptr = blk_alloc_queue(GFP_KERNEL);
	if (NULL == request_queue_ptr)
	{
		ret = -ENOMEM;
		goto out_request_queue_ptr;
	}
	kaka_disk_ptr->addr = 0;
	kaka_disk_ptr->size = PHY_SIZE;
	kaka_disk_ptr->disk_space_tree = RB_ROOT;
	blk_queue_make_request(request_queue_ptr, kaka_blkdev_make_request);
	kaka_disk_ptr->kaka_gendisk = alloc_disk(1);
	if (NULL == kaka_disk_ptr->kaka_gendisk)
	{
		ret = -ENOMEM;
		goto out_kaka_gendisk;
	}
	kaka_disk_ptr->kaka_gendisk->major = kaka_disk_major;
	kaka_disk_ptr->kaka_gendisk->first_minor = 0;
	kaka_disk_ptr->kaka_gendisk->fops = &kaka_blkdev_fops;
	kaka_disk_ptr->kaka_gendisk->queue = request_queue_ptr;
	strcpy(kaka_disk_ptr->kaka_gendisk->disk_name, BLOCK_DEV_NAME);
	set_capacity(kaka_disk_ptr->kaka_gendisk, PHY_SIZE >> SECTOR_SHIFT); //设置有几个扇区
	add_disk(kaka_disk_ptr->kaka_gendisk);
#ifdef DEBUG_KAKA
	memset(read_write_buffer, 0x55, PHY_SIZE);
#endif
	return 0;
out_kaka_gendisk:
	blk_cleanup_queue(request_queue_ptr);
out_request_queue_ptr:
	kfree(kaka_disk_ptr);
out_kaka_disk_ptr:
	unregister_blkdev(kaka_disk_major, BLOCK_DEV_NAME);
out_register_blkdev:
	return ret;
}

static void __exit kakadisk_exit(void)
{
	destroy_block_driver_space(kaka_disk_ptr);
	del_gendisk(kaka_disk_ptr->kaka_gendisk);
	blk_cleanup_queue(kaka_disk_ptr->kaka_gendisk->queue);
	put_disk(kaka_disk_ptr->kaka_gendisk);
	kfree(kaka_disk_ptr);
	unregister_blkdev(kaka_disk_major, BLOCK_DEV_NAME);
}

module_init(kakadisk_init);
module_exit(kakadisk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kaka");