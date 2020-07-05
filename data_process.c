#include "my_block_driver.h"

#ifdef DEBUG_KAKA
extern char read_write_buffer[PHY_SIZE];
#endif

int _do_sector_data_process(struct kaka_disk *kaka_disk_ptr, void *buf, sector_t start_sector, unsigned int len, int dir)
{
	unsigned int total_done = 0;
	unsigned int this_loop_off = (start_sector & SECTOR_MASK) << SECTOR_SHIFT;
	unsigned int this_loop_count = min(len - total_done, (unsigned int)KA_BLOCK_SIZE - this_loop_off);
	BUG_ON(!((dir == 1) || (dir == 0)));
	BUG_ON(start_sector >= (PHY_SIZE >> SECTOR_SHIFT));
	BUG_ON(len > KA_BLOCK_SIZE);
	BUG_ON(buf == NULL);
	BUG_ON(kaka_disk_ptr == NULL);
	while (total_done < len)
	{
		struct my_block_driver_space *my_block_driver_space_ptr = find_disk_sector_space(start_sector, kaka_disk_ptr);
		if (dir == 0) //read
		{
			if (NULL == my_block_driver_space_ptr)
			{
				memset(buf + total_done, 0, this_loop_count);
			}
			else
			{
				void *disk_data_ptr = kmap(my_block_driver_space_ptr->page_ptr);
				void *disk_data_aim_ptr = disk_data_ptr + SECTOR_SIZE * (start_sector & SECTOR_MASK);
				BUG_ON(((unsigned int)disk_data_aim_ptr + this_loop_count) > ((unsigned int)disk_data_ptr + (unsigned int)KA_BLOCK_SIZE));
				memcpy(buf + total_done, disk_data_aim_ptr, this_loop_count);
				kunmap(my_block_driver_space_ptr->page_ptr);
			}
		}
		else //write
		{
			void *disk_data_ptr;
			void *disk_data_aim_ptr;
			BUG_ON(dir != 1);
			if (NULL == my_block_driver_space_ptr)
			{
				int ret;
				my_block_driver_space_ptr = alloc_driver_space(start_sector);
				if (IS_ERR(my_block_driver_space_ptr))
				{
					return PTR_ERR(my_block_driver_space_ptr);
				}
				ret = insert_into_disk_space(my_block_driver_space_ptr, kaka_disk_ptr);
				if (ret < 0)
				{
					destory_one_block_driver_space(my_block_driver_space_ptr);
					return ret;
				}
			}
			disk_data_ptr = kmap(my_block_driver_space_ptr->page_ptr);
			disk_data_aim_ptr = disk_data_ptr + SECTOR_SIZE * (start_sector & SECTOR_MASK);
			BUG_ON(((unsigned int)disk_data_aim_ptr + this_loop_count) > ((unsigned int)disk_data_ptr + (unsigned int)KA_BLOCK_SIZE));
			memcpy(disk_data_aim_ptr, buf + total_done, this_loop_count);
			kunmap(my_block_driver_space_ptr->page_ptr);
		}
		BUG_ON(this_loop_count & ((1 << SECTOR_SHIFT) - 1));
		start_sector += (this_loop_count >> SECTOR_SHIFT);
		total_done += this_loop_count;
		this_loop_count = min(len - total_done, (unsigned int) KA_BLOCK_SIZE);
		BUG_ON(this_loop_count != len - total_done);
	}
	BUG_ON(total_done != len);
	return 0;
}

int do_data_process(struct kaka_disk *kaka_disk_ptr, struct bio_vec *bio_bvec, int rw, sector_t sector)
{
	unsigned int len;
	struct page *page_ptr;
	int ret;
	void *iovec_mem;
	BUG_ON(kaka_disk_ptr == NULL);
	BUG_ON(bio_bvec == NULL);
	len = bio_bvec->bv_len;
	page_ptr = bio_bvec->bv_page;
	iovec_mem = kmap(page_ptr);
	if (iovec_mem == NULL)
	{
		return -ERANGE;
	}
	iovec_mem += bio_bvec->bv_offset;
	ret = _do_sector_data_process(kaka_disk_ptr, iovec_mem, sector , len, rw);
	kunmap(page_ptr);
	return ret;
}