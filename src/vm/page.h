#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <debug.h>
#include <list.h>
#include <hash.h>
#include "threads/palloc.h"

// vm의 type을 3가지로 나눈다. (binary, 매핑된 파일, 스왑으로 가져옴)
enum vm_type{VM_BIN, VM_FILE, VM_ANON};

struct vm_entry{
    uint8_t type; // VM의 type을 저장한다. (binary, 매핑된 파일, 스왑으로 가져옴)
    void *vaddr; // virtual address
    bool writable; // 참인 경우 현 주소에 쓰기가 가능

    bool is_loaded; // 물리메모리가 탑재 되었는지 여부 저장
    struct file *file; // 가상주소와 매핑된 파일 저장

    struct list_elem mmap_elem; // mmap 리스트 요소

    size_t offset; // 파일 오프셋
    size_t read_bytes; // 사용되는 바이트 크기
    size_t zero_bytes; // 남은 바이트 크기
    size_t swap_slot; // 스왑슬롯

    struct hash_elem elem; // 해시 테이블 요소
};

struct file_mem {
    int id;
    struct list_elem elem;
    struct file * file;
    struct list vme_list;
};

// page struct to implement swap
struct page {
    void * addr;
    struct vm_entry * vme;
    struct thread * thread;
    struct list_elem lru_elem;
};

void vm_init (struct hash *vm); // 해시 초기화

bool insert_vme (struct hash *vm, struct vm_entry *vme); // vm에 vme 삽입
bool delete_vme (struct hash *vm, struct vm_entry *vme); // vm의 vme 제거

struct vm_entry *find_vme (void *vaddr); // 현재 스레드의 해시(VM)에 vaddr에 해당되는 vm_entry반환

void vm_destroy (struct hash * vm); // vm 파괴

bool load_file(void *kaddr, struct vm_entry *vme); // 디스크에 존재하는 페이지를 물리 메모리로 로드하는 함수

void do_munmap(struct file_mem *file_mem); //file_mem에 연결된 모든 vm_entry제거 및 페이지 테이블 엔트리 제거.

struct page *alloc_page (enum palloc_flags flag); // page를 새롭게 할당해서 초기화 후 반환
void free_page (void *addr);            // 입력된 addr의 page를 lru_list에서 검색 후 __free_page함수 호출
void __free_page (struct page* page);   // lru_list에서 page 제거 후, page할당 해제

#endif