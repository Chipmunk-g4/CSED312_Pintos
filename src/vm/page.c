#include "page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include <string.h>

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED); //해시 elem e의 vaddr에 대한 해시값 반환
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED); // 입력된 두 hash elem의 vaddr을 비교하여 a가 b보다 작은경우 true, 반대 false 반환
static void hash_destroy_sub (struct hash_elem *e, void *aux UNUSED); // vm_destroy 함수의 hash_destroy 함수를 사용하기 위해서 새롭게 정의된 함수이다.

void vm_init (struct hash *vm){ // 해시 
    // 해시를 초기화 한다.
    // 이때 vm_hash_func, vm_less_func를 인자로 사용하여 해시를 초기화하게 된다.
    hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

bool insert_vme (struct hash *vm, struct vm_entry *vme){ // vm에 vme 삽입
    // vm에 vme의 hash_elem를 삽입한다.
    // 성공한 경우 hash_insert는 NULL을 반환하여 true
    // 실패한 경우 hash_insert는 이미 있는 elem을 반환하여 false
    return hash_insert(vm,&vme->elem) == NULL;
}

bool delete_vme (struct hash *vm, struct vm_entry *vme){ // vm의 vme 제거
    // 해시에서 성공적으로 제거된 경우
    if(hash_delete(vm,&vme->elem)){
        free(vme); // vme의 할당을 해제한다.
        return true;
    }
    else{
        return false;
    }
}

struct vm_entry *find_vme (void *vaddr){ // 현재 스레드의 해시(VM)에 vaddr에 해당되는 vm_entry반환
    
    // vaddr의 페이지 번호를 구해와서 더미 vm_entry의 vaddr로 넣기
    struct vm_entry vme;
    vme.vaddr = pg_round_down (vaddr);

    // 더미 vm_entry인 vme를 통해 현재 스레드에 vaddr를 가지는 vm_entry가 있는지 확인
    struct hash_elem *elem = hash_find (&thread_current ()->VM, &vme.elem);

    // 만약 elem가 존재한다면, hash_entry로 찾아서 반환, 없다면 NULL반환
    return elem ? hash_entry (elem, struct vm_entry, elem) : NULL;
}

void vm_destroy (struct hash *vm){ // vm 파괴
    // hash_destroy함수를 사용하기 위해선, hash_action_func *destructor 인자가 추가로 필요하다.
    // 즉, 이를 위해 새로운 함수 hash_destroy_sub 함수를 만들어 넣는다.
    hash_destroy(vm, hash_destroy_sub);
}

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED){ //해시 elem e의 vaddr에 대한 해시값 반환
    // hash_entry 함수를 사용하여 원소 e의 vaddr를 가져온 후 이를 hash_int로 변환하여 해시값 반환
    void *addr = hash_entry(e,struct vm_entry, elem)->vaddr;
    return hash_int(addr);
}

static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){ // 입력된 두 hash elem의 vaddr을 비교하여 a가 b보다 작은경우 true, 반대 false 반환
    // 원소 a와 b의 vaddr를 가져와 비교한 값을 반환한다.
    void *addr_a = hash_entry(a,struct vm_entry, elem)->vaddr;
    void *addr_b = hash_entry(b,struct vm_entry, elem)->vaddr;
    return addr_a < addr_b;
}

static void hash_destroy_sub (struct hash_elem *e, void *aux UNUSED){ // vm_destroy 함수의 hash_destroy 함수를 사용하기 위해서 새롭게 정의된 함수이다.
    // 이 함수는 hash_elem *e가 입력되었을 때 이를 삭제해야 한다.
    // 즉, e에 해당되는 vm_entry를 가져와 이를 할당 해제하면 된다.
    struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
    free (vme);
}