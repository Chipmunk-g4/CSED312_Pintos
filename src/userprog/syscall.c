#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "threads/malloc.h"

struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);

static struct vm_entry * check_vaddr(const void *vaddr, void* esp);
static void check_valid_buffer(const char *buffer, unsigned size, void *esp, bool write_enabled);
static void check_valid_string(const char *str, void *esp);

static void get_argument(int *esp, int *arg, int count);

static void syscall_halt(void);
static pid_t syscall_exec(const char *);
static int syscall_wait(pid_t);
static bool syscall_create(const char *, unsigned);
static bool syscall_remove(const char *);
static int syscall_open(const char *);
static int syscall_filesize(int);
static int syscall_read(int, void *, unsigned);
static int syscall_write(int, const void *, unsigned);
static void syscall_seek(int, unsigned);
static unsigned syscall_tell(int);

int mmap(int fd, void *addr);
void munmap(int map_id);

/* Registers the system call interrupt handler. */
void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

/* Pops the system call number and handles system call
   according to it. */
static void
syscall_handler(struct intr_frame *f)
{
    void *esp = f->esp;
    int arg[4]; // argument를 저장하는 공간이다.

    check_vaddr(esp, f->esp);

    switch (*(int *)(f->esp)) { // f->esp에는 syscall number가 담겨있다.
    case SYS_HALT:
      syscall_halt();
      break;
    case SYS_EXIT:
      get_argument(f->esp, arg, 1); // 인자: 1개
      syscall_exit(arg[0]);
      break;
    case SYS_EXEC:
      get_argument(f->esp, arg, 1); // 인자: 1개
      check_valid_string((const void *)arg[0], f->esp);
      f -> eax = syscall_exec(arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_WAIT:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_wait(arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_CREATE:
      get_argument(f->esp, arg, 2); // 인자: 2개
      check_valid_string((const void *)arg[0], f->esp);
      f->eax = syscall_create((const char *) arg[0], arg[1]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_REMOVE:
      get_argument(f->esp, arg, 1); // 인자: 1개
      check_valid_string((const void *)arg[0], f->esp);
      f->eax = syscall_remove((const char *) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_OPEN:
      get_argument(f->esp, arg, 1); // 인자: 1개
      check_valid_string((const void *)arg[0], f->esp);
      f->eax = syscall_open((const char *) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_FILESIZE:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_filesize((int) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_READ:
      get_argument(f->esp, arg, 3); // 인자: 3개
      check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, true); // buffer is writeable
      f->eax = syscall_read(arg[0],arg[1],arg[2]);
      break;
    case SYS_WRITE:
      get_argument(f->esp, arg, 3); // 인자: 3개
      check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, false); // buffer is not writeable
      f->eax = syscall_write(arg[0],arg[1],arg[2]);
      break;
    case SYS_SEEK:
      get_argument(f->esp, arg, 2); // 인자: 2개
      syscall_seek((int)arg[0], (unsigned)arg[1]);
      break;
    case SYS_TELL:
      get_argument(f->esp, arg, 1); // 인자: 1개
      f->eax = syscall_tell((int) arg[0]); // 계산 후 결과를 eax에 저장
      break;
    case SYS_CLOSE:
      get_argument(f->esp, arg, 1); // 인자: 1개
      syscall_close((int) arg[0]);
      break;
    case SYS_MMAP:
      get_argument(f->esp, arg, 2); // 인자: 2개
      f->eax = mmap((int)arg[0], (void *)arg[1]);
      break;
    case SYS_MUNMAP:
      get_argument(f->esp, arg, 1); // 인자: 1개
      munmap((int)arg[0]);
      break;
    default:
      // 유효하지 않은 syscall
      syscall_exit(-1);
  }
}

// 유저스택에 있는 데이터를 esp에서 4byte크기로 count개수 만큼 가져온다.
static void get_argument(int *esp, int *arg, int count){

    void *back_up = (void *)esp;

    // every count
    while (count--)
    {
        esp++;
        // check whether bound of esp is legal
        check_vaddr((const void *)(esp), back_up);
        check_vaddr((const void *)(esp+3), back_up);

        // get value
        *(arg++) = *esp;
    }
}

/* Checks user-provided virtual address. If it is
   invalid, terminates the current process. */
static struct vm_entry * check_vaddr(const void *vaddr, void* esp)
{
    // 주소가 user address에 속하는 경우
    if(vaddr >= (void*)0x08048000 && vaddr < (void*)0xc0000000){
        // vaddr가 속한 vm_entry를 가져와서 없다면 (NULL) exit(-1)
        struct vm_entry *vme = find_vme(vaddr);
        if(vme == NULL) syscall_exit(-1);

        return vme;
    }
    // 주소가 user address에 속하지 않는 경우에는 exit
    else{
        syscall_exit(-1);
    }

    return NULL;
}

// read, write syscall에서 버퍼의 주소를 검사하기 위해 사용한다.
static void check_valid_buffer(const char *buffer, unsigned size, void *esp, bool write_enabled){

    struct vm_entry *vme;

    // 버퍼를 확인한다.
    while(size--){
        // 유효한 주소인지 확인
        vme = check_vaddr((void *)(buffer++), esp);
        // writable이 잘 맞는지 확인 (물론 이때 vme는 NULL이 아니다)
        if(write_enabled && !vme->writable) syscall_exit(-1);
    }
}

// exec, create, remove, open syscall에서 문자열의 주소값이 유효한지 판단하는 함수이다.
static void check_valid_string(const char *str, void *esp){
    // str 끝까지 탐색해서 유효한 주소인지 확인
    check_vaddr((void *)(str), esp);
    while(*str != 0){
        str++;
        check_vaddr(str,esp);
    }
}

struct lock *syscall_get_filesys_lock(void)
{
    return &filesys_lock;
}

/* Handles halt() system call. */
static void syscall_halt(void)
{
    shutdown_power_off();
}

/* Handles exit() system call. */
void syscall_exit(int status)
{
    struct process *pcb = thread_get_pcb();

    pcb->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}

/* Handles exec() system call. */
static pid_t syscall_exec(const char *cmd_line)
{
    pid_t pid;
    struct process *child;
    int i;

    pid = process_execute(cmd_line);
    child = process_get_child(pid);

    if (!child || !child->is_loaded)
        return PID_ERROR;

    return pid;
}

/* Handles wait() system call. */
static int syscall_wait(pid_t pid)
{
    return process_wait(pid);
}

/* Handles create() system call. */
static bool syscall_create(const char *file, unsigned initial_size)
{
    bool success;

    lock_acquire(&filesys_lock);
    success = filesys_create(file, (off_t)initial_size);
    lock_release(&filesys_lock);

    return success;
}

/* Handles remove() system call. */
static bool syscall_remove(const char *file)
{
    bool success;

    lock_acquire(&filesys_lock);
    success = filesys_remove(file);
    lock_release(&filesys_lock);

    return success;
}

/* Handles open() system call. */
static int syscall_open(const char *file)
{
    struct file_descriptor_entry *fde;
    struct file *new_file;

    fde = palloc_get_page(0);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);

    new_file = filesys_open(file);
    if (!new_file)
    {
        palloc_free_page(fde);
        lock_release(&filesys_lock);

        return -1;
    }

    fde->fd = thread_get_next_fd();
    fde->file = new_file;
    list_push_back(thread_get_fdt(), &fde->fdtelem);

    lock_release(&filesys_lock);

    return fde->fd;
}

/* Handles filesize() system call. */
static int syscall_filesize(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    int filesize;

    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    filesize = file_length(fde->file);
    lock_release(&filesys_lock);

    return filesize;
}

/* Handles read() system call. */
static int syscall_read(int fd, void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_read, i;

    if (fd == 0)
    {
        unsigned i;

        for (i = 0; i < size; i++)
            *(uint8_t *)(buffer + i) = input_getc();

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    bytes_read = (int)file_read(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_read;
}

/* Handles write() system call. */
static int syscall_write(int fd, const void *buffer, unsigned size)
{
    struct file_descriptor_entry *fde;
    int bytes_written, i;

    if (fd == 1)
    {
        putbuf((const char *)buffer, (size_t)size);

        return size;
    }

    fde = process_get_fde(fd);
    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    bytes_written = (int)file_write(fde->file, buffer, (off_t)size);
    lock_release(&filesys_lock);

    return bytes_written;
}

/* Handles seek() system call. */
static void syscall_seek(int fd, unsigned position)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde)
        return;

    lock_acquire(&filesys_lock);
    file_seek(fde->file, (off_t)position);
    lock_release(&filesys_lock);
}

/* Handles tell() system call. */
static unsigned syscall_tell(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);
    unsigned pos;

    if (!fde)
        return -1;

    lock_acquire(&filesys_lock);
    pos = (unsigned)file_tell(fde->file);
    lock_release(&filesys_lock);

    return pos;
}

/* Handles close() system call. */
void syscall_close(int fd)
{
    struct file_descriptor_entry *fde = process_get_fde(fd);

    if (!fde)
        return;

    lock_acquire(&filesys_lock);
    file_close(fde->file);
    list_remove(&fde->fdtelem);
    palloc_free_page(fde);
    lock_release(&filesys_lock);
}

/*fd와 address를 서로 mapping 해주고, 맵핑 id를 리턴해준다.*/
int mmap(int fd, void *addr) {

  size_t offset = 0;

  // 오류 반환
  if (pg_ofs (addr) != 0 || !addr)    return -1;
  if (is_user_vaddr (addr) == false)  return -1;

  // 새로운 file_mem 할당
  struct file_mem *fm = (struct file_mem *)malloc (sizeof (struct file_mem));
  if (fm == NULL) return -1;

  /* fm의 기본 설정 */
  list_init (&fm->vme_list);

  // fd에 해당하는 파일 열기
  struct file *mmap_file = file_reopen(process_get_fde(fd)->file);
  if(mmap_file == NULL) return -1;

  // 파일 설정 후 file_mem_list에 넣기
  fm->file = mmap_file;
  fm->id = thread_current()->next_mapid++;
  list_push_back (&thread_current()->file_mem_list, &fm->elem);

  // mmap_file의 크기에 맞게 vm_entry 설정해주기
  int length = file_length (mmap_file);
  while(length > 0){
    // 새로운 vme 할당 및 설정
    struct vm_entry *vme = (struct vm_entry *)malloc (sizeof (struct vm_entry));

    // if there already exist => error
    if (find_vme (addr)) return -1;

    vme->type = VM_FILE;
    vme->writable = true;
    vme->is_loaded = false;
    vme->vaddr = addr;
    vme->offset = offset;
    vme->read_bytes = length < PGSIZE ? length : PGSIZE;
    vme->zero_bytes = PGSIZE - vme->read_bytes;
    vme->file = mmap_file;

    // fm의 vme_list과 process의 vm에 방금 만든 따끈따끈한 vme 넣기
    list_push_back (&fm->vme_list, &vme->mmap_elem);
    insert_vme (&thread_current ()->vm, vme);

    // 다음 페이지(가 될 놈)로 이동
    addr += PGSIZE;
    offset += PGSIZE;
    length -= PGSIZE;
  }

  return fm->id;
}

/*map id에 해당하는 memory mapping을 해제한다.*/
void munmap(int map_id) {
  if(map_id < 1)
    return;

  struct list * ml = &(thread_current()->file_mem_list);

  // map_id에 해당하는 file_mem을 찾는다.
  for(struct list_elem *e = list_begin(ml); e != list_end(ml);) {
    struct file_mem * fm = list_entry(e, struct file_mem, elem);

    // list에서 mapping id가 인자로 들어온 map_id와 같을 때
    if(fm->id == map_id) {
      do_munmap(fm);
      file_close(fm->file);
      e = list_remove (e);
      free(fm);

      return;
    }
  }

//  cannot find mapping with map_id
}