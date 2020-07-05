#include "my_block_driver.h"

struct my_block_driver_space *find_disk_sector_space(sector_t sector, struct kaka_disk *kaka_disk_ptr)
{
	struct rb_root *rb_root_ptr = &kaka_disk_ptr->disk_space_tree;
	struct rb_node *node_ptr = rb_root_ptr->rb_node;
	sector_t aim_sector = (sector & ~SECTOR_MASK);
	BUG_ON(sector >= (PHY_SIZE >> SECTOR_SHIFT));
	while (node_ptr)
	{
		struct my_block_driver_space *my_block_driver_space_ptr = container_of(node_ptr, struct my_block_driver_space, node);
		if (my_block_driver_space_ptr->sector == aim_sector)
		{
			return my_block_driver_space_ptr;
		}
		if (aim_sector > my_block_driver_space_ptr->sector)
		{
			node_ptr = node_ptr->rb_right;
		}
		else
		{
			node_ptr = node_ptr->rb_left;
		}
	}
	return NULL;
}

int insert_into_disk_space(struct my_block_driver_space *my_block_driver_space_ptr, struct kaka_disk *kaka_disk_ptr)
{
	struct rb_node **new = &(kaka_disk_ptr->disk_space_tree.rb_node);
	struct rb_node *parent = NULL;
	BUG_ON(my_block_driver_space_ptr->sector >= (PHY_SIZE >> SECTOR_SIZE));
	BUG_ON((my_block_driver_space_ptr->sector & ~SECTOR_MASK) != my_block_driver_space_ptr->sector);
	while (*new)
	{
		struct my_block_driver_space *my_block_driver_space_buffer = container_of(*new, struct my_block_driver_space, node);
		parent = *new;
		if (my_block_driver_space_ptr->sector == my_block_driver_space_buffer->sector)
		{
			pr_info("no need to insert\n");
			return -EINVAL;
		}
		if (my_block_driver_space_ptr->sector > my_block_driver_space_buffer->sector)
		{
			new = &((*new)->rb_right);
		}
		else
		{
			new = &((*new)->rb_left);
		}
	}
	rb_link_node(&my_block_driver_space_ptr->node, parent, new);
	rb_insert_color(&my_block_driver_space_ptr->node, &kaka_disk_ptr->disk_space_tree);
	return 0;
}

struct my_block_driver_space *alloc_driver_space(sector_t sector)
{
	struct my_block_driver_space *my_block_driver_space_ptr;
	BUG_ON(sector >= (PHY_SIZE >> SECTOR_SHIFT));
	my_block_driver_space_ptr = kmalloc(sizeof(struct my_block_driver_space), GFP_KERNEL);
	if (my_block_driver_space_ptr == NULL)
	{
		return ERR_PTR(-ENOMEM);
	}
	my_block_driver_space_ptr->sector = sector & ~SECTOR_MASK;
	my_block_driver_space_ptr->page_ptr = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM, KA_DISK_ORDER);
	if (my_block_driver_space_ptr->page_ptr == NULL)
	{
		kfree(my_block_driver_space_ptr);
		return ERR_PTR(-ENOMEM);
	}
	return my_block_driver_space_ptr;
}

void destory_one_block_driver_space(struct my_block_driver_space *my_block_driver_space_ptr)
{
	BUG_ON(my_block_driver_space_ptr == NULL);
	if (my_block_driver_space_ptr->page_ptr)
	{
		__free_pages(my_block_driver_space_ptr->page_ptr, KA_DISK_ORDER);
	}
	kfree(my_block_driver_space_ptr);
}

void destroy_block_driver_space(struct kaka_disk *kaka_disk_ptr)
{
	struct rb_node *node;
	BUG_ON(kaka_disk_ptr == NULL);
	for (node = rb_first(&kaka_disk_ptr->disk_space_tree); node; )
	{
		struct my_block_driver_space *my_block_driver_space_ptr = rb_entry(node, struct my_block_driver_space, node);
		node = rb_next(node);
		destory_one_block_driver_space(my_block_driver_space_ptr);
	}
}