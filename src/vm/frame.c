#include "vm/frame.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"

// lru_list를 초기화하는 함수
void lru_list_init (void){
    list_init (&lru_list);
    lock_init (&lru_list_lock);
    lru_clock = NULL;
}

// lru_list에 입력된 page를 삽입하는 함수
void insert_page_lru (struct page* page){
    lock_acquire (&lru_list_lock);
    list_push_back (&lru_list, &page->lru_elem);
    lock_release (&lru_list_lock);
}

// lru_list에 입력된 page를 삭제하는 함수
void delete_page_lru (struct page* page){
    // 만약 page가 lru_clock으로 되어있는 경우, lru_clock을 변경한다.
    if(lru_clock == &page->lru_elem)    lru_clock = list_remove (lru_clock);
	else                                list_remove(&page->lru_elem);
}