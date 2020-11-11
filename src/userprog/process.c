#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void argument_stack(char *file_name, void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // argument가 없는 파일 이름을 cmd_name에 저장한다.
  char *saved_ptr;
  char copied_file_name[256]; strlcpy(copied_file_name, file_name, strlen(file_name)+1);
  char *cmd_name = strtok_r(copied_file_name, " ", &saved_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  struct thread *cur = thread_current();

  // argument가 없는 파일 이름을 cmd_name에 저장한다.
  char *saved_ptr;
  char copied_file_name[256]; strlcpy(copied_file_name, file_name, strlen(file_name)+1);
  char *cmd_name = strtok_r(copied_file_name, " ", &saved_ptr);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  cur->load_complete = load (cmd_name, &if_.eip, &if_.esp);

  sema_up (&thread_current()->load_sema);

  if(cur->load_complete){
    // 인자들을 parsing하고, 유저 스택을 채운다.
    argument_stack(file_name, &if_.esp);
  }

  //hex_dump(if_.esp,if_.esp, PHYS_BASE-if_.esp,1);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!cur->load_complete) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

// file_name과 esp를 이용하여 argument들을 parsing하고, 유저 스택에 집어 넣는다.
static void argument_stack(char *file_name, void **esp){
  // argv, argc, 전체 길이 저장
  char ** argv;
  int argc;
  int total_len;

  // 토큰화를 위한 변수들
  char stored_file_name[256];
  char *token;
  char *saved_ptr;
  int i;
  int len;
  
  // 파일 이름을 제외한 토큰들을 준비한다.
  strlcpy(stored_file_name, file_name, strlen(file_name) + 1);
  token = strtok_r(stored_file_name, " ", &saved_ptr);
  argc = 0;

  // token의 개수를 세서 argc의 값을 구한다.
  while (token) {
    argc += 1;
    token = strtok_r(NULL, " ", &saved_ptr);
  }

  // argc의 개수 만큼 저장한 argv의 공간을 마련하고, argv를 구한다.
  argv = (char **)malloc(sizeof(char *) * argc);
  strlcpy(stored_file_name, file_name, strlen(file_name) + 1);
  token = strtok_r(stored_file_name, " ", &saved_ptr);

  for (i = 0; i < argc; i++) {
    // 현재 토큰을 argv에 넣는다.
    argv[i] = token;

    // 다음 토큰
    token = strtok_r(NULL, " ", &saved_ptr);
  }

  // argv를 스택에 push한다. (이때 가장 마지막에 있던 인자부터 push한다.)
  total_len = 0;
  for (i = argc - 1; 0 <= i; i --) {
    // 저장할 위치로 이동
    len = strlen(argv[i]) + 1; // '\0'도 포함되어야 한다.
    *esp -= len;
    // argv[i]를 현재 위치에 저장
    strlcpy(*esp, argv[i], len);
    argv[i] = *esp; // 현재 esp의 위치 값을 argv[i]에 저장한다.
    // 전체 길이에 추가
    total_len += len;
  }
  
  // word align을 push한다. (4의 배수로 맞추기 위해 추가한다.)
  *esp -= (total_len % 4 != 0) ? 4 - (total_len % 4) : 0;

  // Null값을 추가한다.
  *esp -= 4;
  **(uint32_t **)esp = 0;

  // argv값들이 저장된 주소를 저장한다.
  for (i = argc - 1; 0 <= i; i--) {
    *esp -= 4;
    **(uint32_t **)esp = argv[i];
  }

  // argv값들이 저장된 주소들의 주소를 저장한다.
  *esp -= 4;
  **(uint32_t **)esp = *esp + 4;

  // argc의 값을 저장한다.
  *esp -= 4;
  **(uint32_t **)esp = argc;
  
  //  fake address (0)를 저장한다.
  *esp -= 4;
  **(uint32_t **)esp = 0;

  free(argv);
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *child;
  int exit_code;

  // child가 더이상 없는 경우 여기서 종료시킨다.
  if (!(child = thread_get_child(child_tid))){
    return -1;
  }

  // 자식 프로세스가 종료될 때 까지 기다린다.
  sema_down (&child->child_sema);
  // 종료되면 자식 프로세스를 현재 프로세스의 자식 list에서 삭제한다.
  list_remove (&child->child_elem);
  // 자식 프로세스의 exit_code를 얻어온다.
  exit_code = child->exit_code;
  // 자식 프로세스를 완전히 제거하도록 세마포어를 올린다.
  sema_up (&child->parent_sema);
  
  return exit_code;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  int i; // 반복문 전용

  // 파일 디스크립터에 들어있는 STDIN, STDOUT을 제외한 모든 파일을 닫는다.
  for (i = 3; i < 128; i++) {
      if (cur->fd[i] != NULL) {
        file_close(cur->fd[i]);
        cur->fd[i] = NULL;
      }
  } 

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;  
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
//  child process가 종료되었기 떄문에 sema value를 하나 증가시켜 process_wait에서 sema_down을 호출할 수 있도록 한다.
  sema_up(&(cur->child_sema));
//  종료되기 이전에 parent thread에서 값을 모두 읽어와 sema_up을 호출하여 value가 0이 아닐때 까지 wait한다.
  sema_down(&(cur->parent_sema));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
// 성공적으로 파일을 연 경우 file에 쓰기를 방지한다.
//  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
//  load에서 file_close를 호출하고 난 이후에 file write allow를 해준다.
//  file_allow_write(file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

// 파일 객체 f를 입력받아 현재 프로세스의 파일 디스크립터에 입력한다
// 그리고 해당 파일의 fd값을 반환한다.
// 이때 f가 NULL인 경우 -1을 반환한다.
int process_add_file(struct file *f){

  int i;

  // f가 NULL이면 -1을 반환
  if(f == NULL) return -1;

  // 비어있는 곳을 찾아서 넣는다.
  for(i=3;i<128;i++){
    if(thread_current()->fd[i] == NULL){
       thread_current()->fd[i] = f;
       break;
    }
  }

  // fd를 반환한다.
  return i;
}

// 현재 프로세스의 fd값에 해당하는 파일을 불러온다.
// 0,1 (STDIN, STDOUT)에 접근하거나 파일이 없는 index에 접근하는 경우 NULL을 반환한다.
struct file *process_get_file(int fd){

  struct thread *cur = thread_current();
  
  // 0,1 (STDIN, STDOUT)에 접근하거나 파일이 없는 index에 접근하는 경우 NULL을 반환한다.
  if(fd<=1 || cur->fd[fd] == NULL) return NULL;

  // 현재 프로세스의 fd값에 해당하는 파일을 불러온다.
  return cur->fd[fd];
}

// 현재 프로세스의 fd값에 해당하는 파일을 닫는다.
// 0,1 (STDIN, STDOUT)에 접근하거나 파일이 없는 index에 접근하는 경우 무시한다.
void process_close_file(int fd){

  struct thread *cur = thread_current();
  
  // 0,1 (STDIN, STDOUT)에 접근하거나 파일이 없는 index에 접근하는 경우 무시한다.
  if(fd<=1 || cur->fd[fd] == NULL) return;

  // 파일을 닫는다.
  file_close(cur->fd[fd]);
  cur->fd[fd] = NULL;
}