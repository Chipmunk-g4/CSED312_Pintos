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

struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);

static struct vm_entry * check_vaddr(const void *vaddr, void* esp);
static void check_valid_buffer(const char *buffer, unsigned size, void *esp, bool write_enabled);
static void check_valid_string(const char *str, void *esp);


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
    int syscall_num;

    // 주소 유효성 검사
    check_vaddr(esp, f->esp);
    check_vaddr(esp + sizeof(uintptr_t) - 1, f->esp);
    syscall_num = *(int *)esp;

    switch (syscall_num)
    {
    case SYS_HALT:
    {
        syscall_halt();
        NOT_REACHED();
    }
    case SYS_EXIT:
    {
        int status;

        status = *(int *)(esp + sizeof(uintptr_t));

        syscall_exit(status);
        NOT_REACHED();
    }
    case SYS_EXEC:
    {
        char *cmd_line;

        cmd_line = *(char **)(esp + sizeof(uintptr_t));

        // 입력되는 문자열이 유효한지 검사한다.
        check_valid_string((const char *)cmd_line, f->esp);

        f->eax = (uint32_t)syscall_exec(cmd_line);
        break;
    }
    case SYS_WAIT:
    {
        pid_t pid;

        pid = *(pid_t *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_wait(pid);
        break;
    }
    case SYS_CREATE:
    {
        char *file;
        unsigned initial_size;

        file = *(char **)(esp + sizeof(uintptr_t));
        initial_size = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        // 입력되는 문자열이 유효한지 검사한다.
        check_valid_string((const char *)file, f->esp);

        f->eax = (uint32_t)syscall_create(file, initial_size);
        break;
    }
    case SYS_REMOVE:
    {
        char *file;

        file = *(char **)(esp + sizeof(uintptr_t));

        // 입력되는 문자열이 유효한지 검사한다.
        check_valid_string((const char *)file, f->esp);

        f->eax = (uint32_t)syscall_remove(file);
        break;
    }
    case SYS_OPEN:
    {
        char *file;

        file = *(char **)(esp + sizeof(uintptr_t));

        // 입력되는 문자열이 유효한지 검사한다.
        check_valid_string((const char *)file, f->esp);

        f->eax = (uint32_t)syscall_open(file);
        break;
    }
    case SYS_FILESIZE:
    {
        int fd;

        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_filesize(fd);
        break;
    }
    case SYS_READ:
    {
        int fd;
        void *buffer;
        unsigned size;

        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        // 입력되는 버퍼가 유효한지 검사한다.
        check_valid_buffer((const char *)buffer, (unsigned)size, f->esp, false);

        f->eax = (uint32_t)syscall_read(fd, buffer, size);
        break;
    }
    case SYS_WRITE:
    {
        int fd;
        void *buffer;
        unsigned size;

        fd = *(int *)(esp + sizeof(uintptr_t));
        buffer = *(void **)(esp + 2 * sizeof(uintptr_t));
        size = *(unsigned *)(esp + 3 * sizeof(uintptr_t));

        // 입력되는 버퍼가 유효한지 검사한다.
        check_valid_buffer((const char *)buffer, (unsigned)size, f->esp, true);

        f->eax = (uint32_t)syscall_write(fd, buffer, size);
        break;
    }
    case SYS_SEEK:
    {
        int fd;
        unsigned position;
        fd = *(int *)(esp + sizeof(uintptr_t));
        position = *(unsigned *)(esp + 2 * sizeof(uintptr_t));

        syscall_seek(fd, position);
        break;
    }
    case SYS_TELL:
    {
        int fd;
        fd = *(int *)(esp + sizeof(uintptr_t));

        f->eax = (uint32_t)syscall_tell(fd);
        break;
    }
    case SYS_CLOSE:
    {
        int fd;
        fd = *(int *)(esp + sizeof(uintptr_t));

        syscall_close(fd);
        break;
    }
    default:
        syscall_exit(-1);
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
    int i;

    lock_acquire(&filesys_lock);
    success = filesys_create(file, (off_t)initial_size);
    lock_release(&filesys_lock);

    return success;
}

/* Handles remove() system call. */
static bool syscall_remove(const char *file)
{
    bool success;
    int i;

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
    int i;

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
