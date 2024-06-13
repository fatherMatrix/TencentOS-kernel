#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

struct {
  int child2;
  int child4;
} *shm_page;

int fork_sameparent(void) {
  return syscall(__NR_clone, SIGCHLD|CLONE_PARENT, NULL, NULL, NULL, 0);
}

void dump_layout(const char *label) {
  printf("<<<<<<<<<< %s >>>>>>>>>>\n", label);
  system("cat /proc/$PPID/smaps | grep -B10000 '10f000-' | grep -v ' kB$'");
  printf("\n\n\n");
}

int main(void) {
  sync();
  setbuf(stdout, NULL);
  system("cat /proc/$PPID/comm");

  int status;
  eventfd_t dummy_event;

  shm_page = SYSCHK(mmap(NULL, sizeof(*shm_page), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0));

//  SYSCHK(prctl(PR_SET_CHILD_SUBREAPER, 1));

  int evfd = SYSCHK(eventfd(0, EFD_SEMAPHORE));
  int evfd_trigger_leaf_release = SYSCHK(eventfd(0, EFD_SEMAPHORE));
  int evfd_signal_leaf_ready = SYSCHK(eventfd(0, EFD_SEMAPHORE));

  char *p = SYSCHK(mmap((void*)0x100000UL, 0x10000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED_NOREPLACE, -1, 0));
  SYSCHK(mprotect(p+0xf000, 0x1000, PROT_NONE));
  *p = 1; /* alloc root */

  int child1 = SYSCHK(fork()); /* alloc reuse-mid */
  if (child1 == 0) {
    shm_page->child2 = SYSCHK(fork_sameparent()); /* alloc reuse-leaf */
    if (shm_page->child2 == 0) {
      SYSCHK(eventfd_read(evfd, &dummy_event)); /* AWAIT reuse-mid exit */
      int child3 = SYSCHK(fork_sameparent()); /* reuse reuse-mid */
      if (child3 == 0) {
        SYSCHK(eventfd_read(evfd_signal_leaf_ready, &dummy_event));
        dump_layout("reusing reuse-mid");
        SYSCHK(mprotect(p+0x8000, 0x7000, PROT_READ|PROT_WRITE)); /* split reuse-mid */
        dump_layout("split reuse-mid");
        shm_page->child4 = SYSCHK(fork_sameparent()); /* alloc fork-A, fork-B */
        if (shm_page->child4 == 0) {
          dump_layout("allocated fork-A, fork-B");
          p[0x7000] = 1;
          p[0x8000] = 1;
          SYSCHK(eventfd_write(evfd_trigger_leaf_release, 2));
          SYSCHK(eventfd_read(evfd, &dummy_event)); /* AWAIT reuse-leaf exit */
          dump_layout("fork-A and fork-B, reuse-leaf should be released");
          int child5 = SYSCHK(fork_sameparent());
          if (child5 == 0) {
            dump_layout("should now be reusing reuse-leaf for both?");
            SYSCHK(mprotect(p+0x8000, 0x7000, PROT_READ|PROT_WRITE|PROT_EXEC));
            dump_layout("should have merged?");
            SYSCHK(madvise(p+0x7000, 0x2000, 21/*MADV_PAGEOUT*/));
            exit(0);
          }
          exit(0);
        }
        sleep(3);
        exit(0);
      }
      /* bump reuse-leaf degree from 1 to 2 */
      SYSCHK(mprotect(p, 0x1000, PROT_NONE));
      SYSCHK(eventfd_write(evfd_signal_leaf_ready, 1));
      SYSCHK(eventfd_read(evfd_trigger_leaf_release, &dummy_event));
      exit(0); /* reuse-leaf exit */
    }
    sleep(3);
    exit(0); /* reuse-mid exit */
  }
  SYSCHK(waitpid(child1, &status, 0)); /* notice reuse-mid exit */
  SYSCHK(eventfd_write(evfd, 1)); /* SIGNAL reuse-mid exit */
  SYSCHK(waitpid(shm_page->child2, &status, 0)); /* unuse anon_vma 2 */
  //SYSCHK(eventfd_write(evfd, 1)); /* SIGNAL B */

  SYSCHK(eventfd_read(evfd_trigger_leaf_release, &dummy_event));
  SYSCHK(waitpid(shm_page->child4, &status, 0));
  SYSCHK(eventfd_write(evfd, 1)); /* SIGNAL fork anon-VMA gone */

  sleep(3);
}
