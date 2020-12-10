#include "page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <string.h>
#include "vm/swap.h"
#include "userprog/syscall.h"

struct list lru_list;
struct lock lru_lock;
struct page *lru_clock;

static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED); //해시 elem e의 vaddr에 대한 해시값 반환
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux
                         UNUSED); // 입력된 두 hash elem의 vaddr을 비교하여 a가 b보다 작은경우 true, 반대 false 반환
static void
hash_destroy_sub(struct hash_elem *e, void *aux UNUSED); // vm_destroy 함수의 hash_destroy 함수를 사용하기 위해서 새롭게 정의된 함수이다.
struct page *get_next_clock(void);

void lru_list_init() {
  list_init(&lru_list);
  lock_init(&lru_lock);
  lru_clock = NULL;
}

void vm_init(struct hash *vm) { // 해시
  // 해시를 초기화 한다.
  // 이때 vm_hash_func, vm_less_func를 인자로 사용하여 해시를 초기화하게 된다.
  hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

bool insert_vme(struct hash *vm, struct vm_entry *vme) { // vm에 vme 삽입
  // vm에 vme의 hash_elem를 삽입한다.
  // 성공한 경우 hash_insert는 NULL을 반환하여 true
  // 실패한 경우 hash_insert는 이미 있는 elem을 반환하여 false
  return hash_insert(vm, &vme->elem) == NULL;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme) { // vm의 vme 제거
  // 해시에서 성공적으로 제거된 경우
  if (hash_delete(vm, &vme->elem) != NULL) {
    free(vme); // vme의 할당을 해제한다.
    return true;
  } else {
    return false;
  }
}

struct vm_entry *find_vme(void *vaddr) { // 현재 스레드의 해시(VM)에 vaddr에 해당되는 vm_entry반환

  // vaddr의 페이지 번호를 구해와서 더미 vm_entry의 vaddr로 넣기
  struct vm_entry vme;
  vme.vaddr = pg_round_down(vaddr);

  // 더미 vm_entry인 vme를 통해 현재 스레드에 vaddr를 가지는 vm_entry가 있는지 확인
  struct hash_elem *elem = hash_find(&thread_current()->vm, &vme.elem);

  // 만약 elem가 존재한다면, hash_entry로 찾아서 반환, 없다면 NULL반환
  return elem ? hash_entry(elem,
  struct vm_entry, elem) : NULL;
}

void vm_destroy(struct hash *vm) { // vm 파괴
  // hash_destroy함수를 사용하기 위해선, hash_action_func *destructor 인자가 추가로 필요하다.
  // 즉, 이를 위해 새로운 함수 hash_destroy_sub 함수를 만들어 넣는다.
  hash_destroy(vm, hash_destroy_sub);
}

static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED) { //해시 elem e의 vaddr에 대한 해시값 반환
  // hash_entry 함수를 사용하여 원소 e의 vaddr를 가져온 후 이를 hash_int로 변환하여 해시값 반환
  void *addr = hash_entry(e,
  struct vm_entry, elem)->vaddr;
  return hash_int((int) addr);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux
                         UNUSED) { // 입력된 두 hash elem의 vaddr을 비교하여 a가 b보다 작은경우 true, 반대 false 반환
  // 원소 a와 b의 vaddr를 가져와 비교한 값을 반환한다.
  void *addr_a = hash_entry(a,
  struct vm_entry, elem)->vaddr;
  void *addr_b = hash_entry(b,
  struct vm_entry, elem)->vaddr;
  return addr_a < addr_b;
}

static void
hash_destroy_sub(struct hash_elem *e, void *aux UNUSED) { // vm_destroy 함수의 hash_destroy 함수를 사용하기 위해서 새롭게 정의된 함수이다.
  // 이 함수는 hash_elem *e가 입력되었을 때 이를 삭제해야 한다.
  // 즉, e에 해당되는 vm_entry를 가져와 이를 할당 해제하면 된다.
  struct vm_entry *vme = hash_entry(e,
  struct vm_entry, elem);

  // 만약 load되어있는 경우에는 물리메모리를 해제해준다.
  if (vme->is_loaded) {
    palloc_free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
    pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
  }

  free(vme);
}

// 디스크에 존재하는 페이지를 물리 메모리로 로드하는 함수
bool load_file(void *kaddr, struct vm_entry *vme) {
  // 성공하면 true, 실패하면 false를 반환한다.
  // file의 데이터를 offset부터 시작해서 read_bytes만큼 불러왔을 때 read_bytes만큼 제대로 불려와진 경우 => 성공
  if (file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset) == (int) vme->read_bytes) {
    // 물리메모리를 세팅하고, true를 반환한다.
    memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
    return true;
  } else {
    return false;
  }
}

void do_munmap(struct file_mem *file_mem) {
  // file_mem에 속하는 모든 vm_entry 탐색
  for (struct list_elem *e = list_begin(&file_mem->vme_list); e != list_end(&file_mem->vme_list);) {
    // e를 통해 vm_entry 가져오기
    struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);

    // vme가 현재 load된 상태일 때
    if (vme->is_loaded) {
      void *paddr = pagedir_get_page(thread_current()->pagedir, vme->vaddr);

      // 만약 dirty_bit가 켜져있다면 디스크에 write
      if (pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)) {
        lock_acquire(&filesys_lock);
        file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
        lock_release(&filesys_lock);
      }
      // 페이지 테이블 해제
      pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
      // 물리 메모리 할당 해제
      free_page(paddr);
    }
    // 설정 해제
    vme->is_loaded = false;
    e = list_remove(e);
    delete_vme(&thread_current()->vm, vme);
  }
}

void insert_page(struct page *page) {
  if (page != NULL) {
    lock_acquire(&lru_lock);
    list_push_back(&lru_list, &(page->lru_elem));
    lock_release(&lru_lock);
  }
}

void delete_page(struct page *page) {
  if (page != NULL) {
    if (lru_clock == page)
      lru_clock = list_entry(list_next(&page->lru_elem), struct page, lru_elem);
    list_remove(&(page->lru_elem));
  }
}

// palloc_get_page의 wrapper 함수.
// Swap out을 통해 physical page가 없어라도 할당 가능하게 해준다.
struct page *alloc_page(enum palloc_flags flags) {
  void *addr = palloc_get_page(flags);
  // if there's no physical pages, perform swap out until get pages
  while (addr == NULL) {
    perform_swap_out();
    addr = palloc_get_page(flags);
  }
  struct page *p = (struct page *) malloc(sizeof(struct page));
  // initialize page's field
  p->addr = addr;
  p->thread = thread_current();
  // insert page into lru list
  insert_page(p);
  return p;
}


void free_page(void *addr) {
  lock_acquire(&lru_lock);
  for (struct list_elem *e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
    struct page *p = list_entry(e, struct page, lru_elem);
    if (p->addr == addr) {
      palloc_free_page(addr);
      delete_page(p);
      free(p);
      break;
    }
  }
  lock_release(&lru_lock);
}

// 다음 clock을 찾아 lru_clock을 업데이트 하고 실패할 경우 NULL을 return 한다.
struct page *get_next_clock(void) {
//  initially when lru clock is null
  if (lru_clock == NULL) {
//    if there's no element in list, return null
    if (list_size(&lru_list) == 0)
      return NULL;
    lru_clock = list_entry(list_begin(&lru_list), struct page, lru_elem);
    return lru_clock;
  }

//  single element in list and next element is itself
  if (list_size(&lru_list) == 1)
    return NULL;

//  get next clock
  struct list_elem *e = list_next(&(lru_clock->lru_elem));
//  if current element was last
  if (e == list_end(&lru_list)) {
    e = list_begin(&lru_list);
  }
  lru_clock = list_entry(e, struct page, lru_elem);
  return lru_clock;
}

void perform_swap_out(void) {
  lock_acquire(&lru_lock);

  while (true) {
    struct page *p = get_next_clock();
    if (p == NULL) break;

    if (pagedir_is_accessed(p->thread->pagedir, p->vme->vaddr)) {
      pagedir_set_accessed(p->thread->pagedir, p->vme->vaddr, false);
      continue;
    }

    // if reaches here, victim is selected
    // if dirty bit true or it's swap type

    if (pagedir_is_dirty(p->thread->pagedir, p->vme->vaddr) || p->vme->type == VM_ANON) {
      // if file type, write back
      if (p->vme->type == VM_FILE) {
        lock_acquire(&filesys_lock);
        file_write_at(p->vme->file, p->addr, p->vme->read_bytes, p->vme->offset);
        lock_release(&filesys_lock);
      }
        // binary or swap type, then swap out
      else {
        p->vme->type = VM_ANON;
        p->vme->swap_slot = swap_out(p->addr);
      }
    }

    p->vme->is_loaded = false;

    //clear physical page
    pagedir_clear_page(p->thread->pagedir, p->vme->vaddr);
    palloc_free_page(p->addr);
    delete_page(p);
    free(p);

    break;
  }
  lock_release(&lru_lock);
}