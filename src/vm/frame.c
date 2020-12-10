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

// Clock 알고리즘을 수행할 때 lru_list의 다음 원소로 이동하는 역할을 하는 함수이다.
// 호출시 lru_list에서 다음 위치를 반환한다.
struct list_elem *get_next_lru_clock (){

    // 만약 현재 lru_clock이 비어있는 경우
    if(lru_clock == NULL){
        // 만약 lru_list가 비어있는 경우 NULL반환
        if(list_empty (&lru_list)){
            return NULL;
        }
        // 그렇지 않은 경우 lru_list의 첫번째 원소를 반환
        else{
            return (lru_clock = list_begin(&lru_list));
        }
    }

    // 다음 원소로 이동
    struct list_elem *e = list_next(lru_clock);

    // 만약 lru_clock이 lru_list의 마지막에 도착한 경우
    if(e == list_end(&lru_list)){
        // 만약 lru_list에 페이지가 한개만 있는 경우 NULL반환
		if(lru_clock == list_begin(&lru_list)){
			return NULL;
		}
        // 그렇지 않은 경우 lru_list의 시작지점 설정
		else{
			e = list_begin(&lru_list);
		}
    }
    lru_clock = e;
    return e;
}