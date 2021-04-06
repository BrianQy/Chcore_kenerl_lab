#include <common/util.h>
#include <common/macro.h>
#include <common/kprint.h>

#include "buddy.h"

/*
 * The layout of a phys_mem_pool:
 * | page_metadata are (an array of struct page) | alignment pad | usable memory |
 *
 * The usable memory: [pool_start_addr, pool_start_addr + pool_mem_size).//所用内存范围
 */
void init_buddy(struct phys_mem_pool *pool, struct page *start_page,
		vaddr_t start_addr, u64 page_num)//poll 内存池 startpage 起始页的页指针 startaddr 起始地址 pagenum 页数
{
	int order;//阶
	int page_idx;//index
	struct page *page;//页

	/* Init the physical memory pool. 初始化物理内存池*/
	pool->pool_start_addr = start_addr;
	pool->page_metadata = start_page;//元数据
	pool->pool_mem_size = page_num * BUDDY_PAGE_SIZE;
	/* This field is for unit test only. */
	pool->pool_phys_page_num = page_num;

	/* Init the free lists */
	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		pool->free_lists[order].nr_free = 0;
		init_list_head(&(pool->free_lists[order].free_list));
	}

	/* Clear the page_metadata area. */
	memset((char *)start_page, 0, page_num * sizeof(struct page));

	/* Init the page_metadata area. */
	for (page_idx = 0; page_idx < page_num; ++page_idx) {
		page = start_page + page_idx;//指针运算
		page->allocated = 1;//set 1
		page->order = 0;//set0
	}

	/* Put each physical memory page into the free lists. */
	for (page_idx = 0; page_idx < page_num; ++page_idx) {
		page = start_page + page_idx;
		buddy_free_pages(pool, page);
	}
}

static struct page *get_buddy_chunk(struct phys_mem_pool *pool,
				    struct page *chunk)//得到兄弟chunk 伙伴索引
{
	u64 chunk_addr;
	u64 buddy_chunk_addr;
	int order;

	/* Get the address of the chunk. */
	chunk_addr = (u64) page_to_virt(pool, chunk);
	order = chunk->order;
	/*
	 * Calculate the address of the buddy chunk according to the address
	 * relationship between buddies.//计算得到有兄弟关系的另一个块
	 */
#define BUDDY_PAGE_SIZE_ORDER (12)
	buddy_chunk_addr = chunk_addr ^
	    (1UL << (order + BUDDY_PAGE_SIZE_ORDER));//无符号长整数

	/* Check whether the buddy_chunk_addr belongs to pool. */
	if ((buddy_chunk_addr < pool->pool_start_addr) ||
	    (buddy_chunk_addr >= (pool->pool_start_addr +
				  pool->pool_mem_size))) {
		return NULL;
	}

	return virt_to_page(pool, (void *)buddy_chunk_addr);
}

/*
 * split_page: split the memory block into two smaller sub-block, whose order
 * is half of the origin page.
 * pool @ physical memory structure reserved in the kernel
 * order @ order for origin page block
 * page @ splitted page
 * 
 * Hints: don't forget to substract the free page number for the corresponding free_list.
 * you can invoke split_page recursively until the given page can not be splitted into two
 * smaller sub-pages.
 */
static struct page *split_page(struct phys_mem_pool *pool, u64 order,
			       struct page *page)//order 为目标order page为被分裂的page
{
	// <lab2>

	/* Deal with error */
	if(page->allocated == 1 || page->order <=0 || page->order <= order){
		return page;//can not be splitted
	}

	/* Deal with recurse */
	if(page->order - order > 1){//目标分割需要多次 递归调用
		page = split_page(pool, order+1, page);//一次分割只减一半
	}

	/* Init data */
	int new_order = order - 1;//2次幂-1即为减半
	struct free_list* origin_order_free_list = &(pool->free_lists[page->order]);
	struct free_list* splite_order_free_list = &(pool->free_lists[new_order]);

	/* Deal with origin page */
	page->order = new_order;
	origin_order_free_list->nr_free -- ;
	list_del(&page->node);//删除原节点

	/* Deal with new splited buddy page */
	struct page *split_buddy_page = get_buddy_chunk(pool, page);//建立索引
	split_buddy_page->order = new_order;//update order
	split_buddy_page->allocated = page->allocated;//update allocated (always 0)

	/* Deal with two budder pages' node */
	splite_order_free_list->nr_free += 2;
	list_add(&page->node, &splite_order_free_list->free_list);
	list_add(&split_buddy_page->node, &splite_order_free_list->free_list);
	
	return split_buddy_page;
	// </lab2>
}

/*
 * buddy_get_pages: get free page from buddy system.
 * pool @ physical memory structure reserved in the kernel
 * order @ get the (1<<order) continous pages from the buddy system
 * 
 * Hints: Find the corresonding free_list which can allocate 1<<order
 * continuous pages and don't forget to split the list node after allocation   
 */
struct page *buddy_get_pages(struct phys_mem_pool *pool, u64 order)
{
	// <lab2> 从空闲链表里拿到空闲的块 
	/* Deal with error situation */
	if(order >= BUDDY_MAX_ORDER ){
		return NULL;
	}

	/* Init page */
	struct page *page = NULL;
	page->allocated = 0;
	page->order = order;

	//存在合适的块 直接分配
	if(pool->free_lists[order].nr_free != 0) {
		struct list_head *list_node = pool->free_lists[order]->free_list.next;//指针指向所需的块的下一个
		page = list_entry(list_node,struct page,node); //使用pointer应用到对象（page）
		pool->free_lists[order]->nr_free --;//number参数-1
		list_del(list_node);//释放节点
	}else {//不存在合适的块 需要由更大的分裂
		u64 i = 0;
		while(pool->free_lists[order+i].nr_free <=0 && (order+i) > BUDDY_MAX_ORDER ){//找更大的存在freeblock的order
			i++;	
		}
		u64 big_order = order + i;
		if( big_order >= BUDDY_MAX_ORDER ){
			return NULL;
		}
		/* Get the mem we need to create a temp page*/
		struct page *splited_page = NULL;
		struct list_head *list_node = pool->free_lists[big_order]->free_list.next;//指针指向所需的块的下一个
		splited_page = list_entry(list_node,struct page,node); //使用pointer应用到对象（page）
		pool->free_lists[big_order]->nr_free --;//number参数-1
		list_del(list_node);//释放节点

		/* Split the temp page to get the one we actually need */
		page = split_page(pool,order,splited_page);
	}
	return page;
	// </lab2>
}

/*
 * merge_page: merge the given page with the buddy page
 * pool @ physical memory structure reserved in the kernel
 * page @ merged page (attempted)
 * 
 * Hints: you can invoke the merge_page recursively until
 * there is not corresponding buddy page. get_buddy_chunk
 * is helpful in this function.
 */
static struct page *merge_page(struct phys_mem_pool *pool, struct page *page)
{
	// <lab2>

	struct page *merge_page = NULL;
	struct page *buddy_page = get_buddy_chunk(pool,page);
	/* Deal with Error */
	if(page->order >= BUDDY_MAX_ORDER - 1 || page->allocated ){
		return page;
	}
	if(buddy_page->allocated || buddy_page == NULL || buddy_page->order != page->order){//如果兄弟节点之间order不同 或 找不到buddy
		return NULL;
	}
	/* Deal with the process */
	struct list_head origin_free_list = &(pool->free_lists[page->order]);//原始位置
	struct list_head merge_free_list = &(pool->free_lists[page->order + 1]);//目标位置  

	origin_free_list->nr_free -= 2;//减掉自身和buddy
	list_del(page->node);
	list_del(buddy_page->node);

	merge_free_list->nr_free ++;

	/* Init new merge one */
	merge_page->order = page->order + 1;
	merge_page->allocated = 0;
	merge_page->node = merge_free_list;
	list_add(&merge_page->node, &merge_free_list->free_list);

	/* Deal with the recurse */
	return merge_page(pool,merge_page);
	// </lab2>
}

/*
 * buddy_free_pages: give back the pages to buddy system
 * pool @ physical memory structure reserved in the kernel
 * page @ free page structure
 * 
 * Hints: you can invoke merge_page.
 */
void buddy_free_pages(struct phys_mem_pool *pool, struct page *page)
{
	// <lab2>

	// </lab2>
}

void *page_to_virt(struct phys_mem_pool *pool, struct page *page)
{
	u64 addr;

	/* page_idx * BUDDY_PAGE_SIZE + start_addr */
	addr = (page - pool->page_metadata) * BUDDY_PAGE_SIZE +
	    pool->pool_start_addr;
	return (void *)addr;
}

struct page *virt_to_page(struct phys_mem_pool *pool, void *addr)
{
	struct page *page;

	page = pool->page_metadata +
	    (((u64) addr - pool->pool_start_addr) / BUDDY_PAGE_SIZE);
	return page;
}

u64 get_free_mem_size_from_buddy(struct phys_mem_pool * pool)
{
	int order;
	struct free_list *list;
	u64 current_order_size;
	u64 total_size = 0;

	for (order = 0; order < BUDDY_MAX_ORDER; order++) {
		/* 2^order * 4K */
		current_order_size = BUDDY_PAGE_SIZE * (1 << order);
		list = pool->free_lists + order;
		total_size += list->nr_free * current_order_size;

		/* debug : print info about current order */
		kdebug("buddy memory chunk order: %d, size: 0x%lx, num: %d\n",
		       order, current_order_size, list->nr_free);
	}
	return total_size;
}
