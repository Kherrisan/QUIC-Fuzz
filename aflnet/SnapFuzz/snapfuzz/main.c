/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "real_syscall.h"
#include "sbr_api_defs.h"

#define __STDC_WANT_LIB_EXT2__ 1
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <libgen.h>
#undef basename

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/limits.h>
#include <linux/unistd.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/uio.h>

// TODO: dl_open() is very slow because of SaBRe's mmap interception and syscall
// discovery.
// TODO: Support AFL dump mode.

// QUIC-Fuzz notes:
// syscall() is libc function which set the errno value and return -1
// real_syscall() does not set the errno value and return it directly.
// smart defer fork server does not work with target not instrumented using llvm mode.

static atomic_bool defer_done = false;

#ifdef SF_STDIO
static int target_log_sock = -1;
#endif // SF_STDIO

#ifdef SF_MEMFS
#include "libsqlfs/sqlfs.h"

#define SBR_FILES_MAX 400

// TODO: Do I realy need this? a) can libsqlfs understand rel paths? b) can I do
// this as string concat?
#define TO_ABS_PATH(rel_path, abs_path)                                        \
  do {                                                                         \
    if (starts_with(rel_path, "/") && strstr(rel_path, "..") == NULL) {        \
      strncpy(abs_path, rel_path, PATH_MAX);                                   \
      abs_path[PATH_MAX - 1] = '\0';                                           \
    } else {                                                                   \
      char *rv = realpath(rel_path, abs_path);                                 \
      if (rv == NULL && errno != ENOENT) {                                     \
        if (errno == ENAMETOOLONG) {                                           \
          return -1;                                                           \
        }                                                                      \
        perror("realpath() failed");                                           \
        exit(EXIT_FAILURE);                                                    \
      }                                                                        \
    }                                                                          \
  } while (0)

static sqlfs_t *sqlfs = NULL;
// FDs never used are -1.
static char mem_fds_open[SBR_FILES_MAX] = {-1};

struct memfd {
  int fd;
  int flags;
  char *name;
};
static struct memfd memfds_preinit[100] = {0};
static int nmemfds = 0;

static bool starts_with(const char *str, const char *pre) {
  if (!str || !pre)
    return false;
  size_t lenstr = strlen(str);
  size_t lenprefix = strlen(pre);
  if (lenprefix > lenstr)
    return false;
  return strncmp(pre, str, lenprefix) == 0;
}

static void copy_files(int read_fd, char write_fd) {
  struct stat stat_buf;
  off_t offset = 0;
  fstat(read_fd, &stat_buf);
  int n = sendfile(write_fd, read_fd, &offset, stat_buf.st_size);
  assert(n == stat_buf.st_size);
}

// How memfd dance works:
// We want to replace the underlying memory file with a copy of it.
// 1) Before afl_manual_init(), keep track of all memfds.
// 2) At afl_manual_init(), create a new memfd for each old one.
// 3) Copy all data from old memfds to the new ones.
// 4) dup() all old memfds.
// 5) close() all old memfds.
// 6) dup2() new memfds to numbers equal to old memfds.
// We don't close() the new memfds.
void memfds_dance() {
  for (size_t i = 0; i < nmemfds; i++) {
    struct memfd oldmemfd = memfds_preinit[i];

    int oldfd = oldmemfd.fd;
    int n_oldfd = dup(oldfd);

    int newfd = memfd_create(oldmemfd.name, oldmemfd.flags);
    newfd = dup2(newfd, oldfd);
    copy_files(n_oldfd, newfd);
  }
}

int iopenat(int dirfd, const char *pathname, int flags, mode_t mode) {
  // TODO: What if we read the file multiple times?

  if (starts_with(pathname, "/dev/") || starts_with(pathname, "/etc/")) {
    // assert((flags & O_ACCMODE) == O_RDONLY);
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  }

  // Optimization: If we are after forkserver and we are just reading a file,
  // let is just open in the real FS. Don't go through the whole memfd + sqlfs.
  if (defer_done && ((flags & O_ACCMODE) == O_RDONLY)) {
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  }

  // NOTE: If the file doesn't exist, this is UB... For now we just ignore it...
  // e.g. this won't work: "../fake/../test". Only the first dots will be
  // resolved.
  char abs_pathname[PATH_MAX];
  TO_ABS_PATH(pathname, abs_pathname);

  // If the file exist in memory, retrieve it.
  key_attr attr = {0};
  if (sqlfs_get_attr(sqlfs, abs_pathname, &attr) == 1) {
    if (S_ISREG(attr.mode)) {
      char id[sizeof(int)] = {0};
      sqlfs_proc_read(sqlfs, abs_pathname, id, sizeof(int), 0, NULL);
      int fd = *(int *)(id);
      if (mem_fds_open[fd] == true) {
        // NOTE: We can't support opening the same file multiple times.
        assert(false);
      }
      mem_fds_open[fd] = true;
      return fd;
    } else {
      assert(false);
    }
  }

  // Else, check if we need to execute a real syscall, or write in memory.
  if (!(flags & O_WRONLY) && !(flags & O_RDWR)) {
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  }

  // If file doesn't exist and we are going to write, create it.
  char *pathname_dup = strdup(abs_pathname);
  assert(pathname_dup != NULL);
  int rc = sqlfs_proc_mkdir(sqlfs, dirname(pathname_dup), 0777);
  assert(rc == 0 || rc == -EEXIST);
  free(pathname_dup);

  int memflags = 0;
  if (flags | O_CLOEXEC)
    memflags = MFD_CLOEXEC;
  int newfd = memfd_create(abs_pathname, memflags);
  assert(newfd < SBR_FILES_MAX);
  mem_fds_open[newfd] = true;
  if (!defer_done) {
    char *cpname = strdup(abs_pathname);
    assert(cpname != NULL);
    memfds_preinit[nmemfds] =
        (struct memfd){.fd = newfd, .flags = memflags, .name = cpname};
    nmemfds++;
  }

  rc = sqlfs_proc_write(sqlfs, abs_pathname, (char *)&newfd, sizeof(int), 0,
                        NULL);
  assert(rc == sizeof(int));

  // If file exists in the real FS we need to copy it's content.
  if (access(abs_pathname, F_OK) == 0) {
    char buf[8192];
    int realfile = open(abs_pathname, O_RDONLY);
    assert(realfile > 0);
    size_t nread;
    do {
      // TODO:
      // https://eklausmeier.wordpress.com/2016/02/03/performance-comparison-mmap-versus-read-versus-fread/
      nread = read(realfile, buf, sizeof(buf));
      assert(nread >= 0);
      int nwrite = write(newfd, buf, nread);
      assert(nwrite == nread);
    } while (nread > 0);
    close(realfile);
  }

  return newfd;
}

int icreat(const char *pathname, mode_t mode) {
  return iopenat(AT_FDCWD, pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int i_l_stat(int sysno, const char *pathname, struct stat *statbuf) {
  char abs_pathname[PATH_MAX];
  TO_ABS_PATH(pathname, abs_pathname);

  key_attr attr = {0};
  // HINT: Don't use sqlfs_proc_statfs it doesn't support ":memory:".
  if (sqlfs_get_attr(sqlfs, abs_pathname, &attr) == 1) {
    if (S_ISDIR(attr.mode)) {
      statbuf->st_dev = makedev(0, 49);
      statbuf->st_nlink = 1;
      statbuf->st_blksize = 4096;
      statbuf->st_blocks = 8;

      statbuf->st_ino = attr.inode;
      statbuf->st_mode = attr.mode;
      statbuf->st_uid = attr.uid;
      statbuf->st_gid = attr.gid;
      statbuf->st_size = attr.size;
      statbuf->st_atime = attr.atime;
      statbuf->st_mtime = attr.mtime;
      statbuf->st_ctime = attr.ctime;
      return 0;
    } else {
      char id[sizeof(int)] = {0};
      sqlfs_proc_read(sqlfs, abs_pathname, id, sizeof(int), 0, NULL);
      return real_syscall(SYS_fstat, *(int *)(id), (long)statbuf, 0, 0, 0, 0);
    }
  }
  return real_syscall(sysno, (long)pathname, (long)statbuf, 0, 0, 0, 0);
}

// TODO: Memory only increases as we don't ever close the memfd.
int iunlink(const char *pathname) {
  char abs_pathname[PATH_MAX];
  TO_ABS_PATH(pathname, abs_pathname);

  int rc = sqlfs_proc_unlink(sqlfs, abs_pathname);
  // We don't check to verify rc as some apps just blindly delete files (e.g.
  // pid files in /var/run).
  // assert(rc == 0);

  return rc;
}

// TODO: Support AT_REMOVEDIR
int iunlinkat(int dirfd, const char *pathname, int flags) {
  assert(false);
  assert((flags & AT_REMOVEDIR) == 0);
  return iunlink(pathname);
}

int imkdir(const char *pathname, mode_t mode) {
  char abs_pathname[PATH_MAX];
  TO_ABS_PATH(pathname, abs_pathname);

  return sqlfs_proc_mkdir(sqlfs, abs_pathname, mode);
}

int irmdir(const char *pathname) {
  char abs_pathname[PATH_MAX];
  TO_ABS_PATH(pathname, abs_pathname);

  return sqlfs_proc_rmdir(sqlfs, abs_pathname);
}
#endif // SF_MEMFS

#define AFL_DATA_SOCKET 200
#define AFL_CTL_SOCKET (AFL_DATA_SOCKET + 1)
#define FORKSRV_FD_1 198
#define FORKSRV_FD_2 (FORKSRV_FD_1 + 1)
#define RANDOM_PEER_ACCEPT_PORT 2321
// QUIC-Fuzz ADDED HERE
#define MAX_SERVER_RECV_SKIP 1

typedef enum { Send, Recv } SbrState;
typedef enum { NoAcceptYet, Accepted, Done } CommsState;

static int afl_sock = AFL_DATA_SOCKET;
static int dbg_sock = -1;
// QUIC-Fuzz ADDED HERE
static int skip_recv_ret_val = 0;
// store the SO_SNDBUF and SO_RECVBUF
static const int so_send_buf = 10240;
static const int so_receive_buf = 10240; // same size as tmp_msg_buf

// We trap the target's listen socket (ie we allow it to connect and we
// substitute the fd in read/write syscalls) in order to provide realistic
// configuration options.
static int target_listen_sock = -1;
static int epoll_sock = -1;

// make sure one send one recv
static bool is_server_send_now = 0;
static int server_receive_skip_count = 0;

// keep track whether we need to include these in name_addr and cmsg
// can we assume that recvfrom(), recvmsg() and recvmmsg() will always called after all setsockopt?
static int is_ipv6 = 0;
static int require_ip_pktinfo = 0;
static int require_ipv6_pktinfo = 0;
static int require_ip_tos = 0;
static int require_ipv6_tclass = 0;
static struct epoll_event afl_sock_event;

static _Thread_local CommsState cs = NoAcceptYet;

// Unfortunately when we use SOCK_SEQPACKET we need to take packages at once.
static _Thread_local bool pending_buf = false;
static _Thread_local size_t idx = 0, maxidx = 0;
// QUIC-Fuzz EDITED HERE
static _Thread_local char tmpbuf[10240] = {0}; // 25000
// QUIC-Fuzz ADDED HERE
static _Thread_local unsigned char tmp_msg_buf[10240] = {0}; // we use 10KB, increase this will likely to decrease execution speed

static pthread_mutex_t lock;

extern void __afl_manual_init(void) __attribute__((weak));

// fill in the hardcoded source addr name for recvfrom(), recvmsg(), recvmmsg()
static socklen_t fill_addr_name(void *src_addr){
  if(src_addr == NULL){
    return 0;
  }

  if(is_ipv6){
    // IPv6
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6*)src_addr;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(3344);
    inet_pton(AF_INET6, "::1", &addr6->sin6_addr);
    return sizeof(struct sockaddr_in6);

  }else{
    // IPv4
    struct sockaddr_in *addr4 = (struct sockaddr_in*)src_addr;
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(3344);
    inet_pton(AF_INET, "127.0.0.1", &addr4->sin_addr);
    return sizeof(struct sockaddr_in);

  } 
}

// fill in the require cmsg that was requestg when setsockopt()
// use in recvmsg(), recvmmsg()
static int fill_cmsg(struct msghdr *msg){
  size_t cmsg_len = 0;
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

  if(require_ipv6_pktinfo && cmsg != NULL){
    // packet info for IPv6
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo *pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in6_pktinfo));
    inet_pton(AF_INET6, "::1", &pktinfo->ipi6_addr);
    pktinfo->ipi6_ifindex = 1;
    cmsg_len += CMSG_SPACE(sizeof(struct in6_pktinfo));
    cmsg = CMSG_NXTHDR(msg, cmsg);
  }
  
  if(require_ip_pktinfo && cmsg != NULL){
    // packet info for IPv4
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo *pktinfo = (struct in_pktinfo *) CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in_pktinfo));
    inet_pton(AF_INET, "127.0.0.1", &pktinfo->ipi_addr);
    pktinfo->ipi_ifindex = 1;
    cmsg_len += CMSG_SPACE(sizeof(struct in_pktinfo));
    cmsg = CMSG_NXTHDR(msg, cmsg);
  }

  if(require_ipv6_tclass && cmsg != NULL){
    // traffic class for IPv6
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_TCLASS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint8_t));
    uint8_t *traffic_class = (uint8_t *) CMSG_DATA(cmsg);
    *traffic_class = 0x00;
    cmsg_len += CMSG_SPACE(sizeof(uint8_t));
    cmsg = CMSG_NXTHDR(msg, cmsg);
  }
  
  if(require_ip_tos && cmsg != NULL){
    // THIS may CAUSE QUICLY TO CRASHHHHHHH
    // TOS for IPv4
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_TOS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint8_t));
    uint8_t *traffic_class = (uint8_t *) CMSG_DATA(cmsg);
    *traffic_class = 0x00;
    cmsg_len += CMSG_SPACE(sizeof(uint8_t));
    cmsg = CMSG_NXTHDR(msg, cmsg);
  }

  msg->msg_controllen = cmsg_len;

  return 0;
}

static void afl_manual_init() {
// #ifdef __AFL_HAVE_MANUAL_CONTROL
  if (!defer_done) {
    defer_done = true;
    pid_t forkserverpid = getpid();
    __afl_manual_init();
    // AFL's forkerver should never reach this point and thus we are the
    // afl-forkserver's child.
    assert(forkserverpid != getpid());

    // TODO: Will this create issues with kill the forkserver? If the forkserver
    // gets a (-forkserver_pid, SIGKILL) will this kill it's children?
    setpgid(0, 0);

#ifdef SF_MEMFS
    if (nmemfds > 0)
      memfds_dance();
#endif // SF_MEMFS
  }
// #endif
}

// The first action the sbr-protocol expects is either a send or a recv. No
// deferring should happen after this. The earlier deferring that can possibly
// happen can also a be just before a clone().
static void notify_a_send() {
#ifdef SF_SMARTDEFER
  afl_manual_init();
#endif // SF_SMARTDEFER

  SbrState st = Send;

  ssize_t rc = send(AFL_CTL_SOCKET, &st, sizeof(SbrState), MSG_NOSIGNAL);
  assert(rc == sizeof(SbrState));
}

static void notify_a_recv() {
#ifdef SF_SMARTDEFER
  afl_manual_init();
#endif // SF_SMARTDEFER

  SbrState st = Recv;
  ssize_t rc = send(AFL_CTL_SOCKET, &st, sizeof(SbrState), MSG_NOSIGNAL);
  assert(rc == sizeof(SbrState));
}

int isocket(int domain, int type, int protocol) {
  int rc = syscall(SYS_socket, domain, type, protocol);

  // FILE *file= fopen("output.txt", "a");
  // fprintf(file, "Created a socket with %d fd\n", rc);
  // fclose(file);

  // Servers might open multiple sockets. The DNS benchmark listens to both
  // SOCK_STREAM and SOCK_DGRAM which leads to overwriting the first
  // target_listen_sock from SOCK_STREAM, to the SOCK_DGRAM one. To avoid this
  // we just follow the first registered socket.
  // TODO: Should we accept more than 1 socket? How will we handle it?
  if (target_listen_sock != -1){
    return rc;
  }

  if (domain == AF_INET && ((type & SOCK_STREAM) == SOCK_STREAM)) {
    target_listen_sock = rc;
  } else if ((domain == AF_INET || domain == AF_INET6) && ((type & SOCK_DGRAM) == SOCK_DGRAM)) {
    target_listen_sock = rc;
    // SOCK_DGRAM doesn't require an accept(). Thus we emulate an accept here.
    cs = Accepted;
    rc = afl_sock;

    // hardcoded addr_name for recvfrom(), recvmsg() and recvmmsg()
    if(domain == AF_INET6){
      pthread_mutex_lock(&lock);
      is_ipv6 = 1;
      pthread_mutex_unlock(&lock);
    }

    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "This is afl_sock\n");
    // fclose(file);
  }

  return rc;
}

int ibind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (sockfd == afl_sock) {
    // This will happen only when we are in SOCK_DGRAM.
    return 0;
  }
  return real_syscall(SYS_bind, sockfd, (long)addr, addrlen, 0, 0, 0);
}

int igetsockopt(int sockfd, int level, int optname, void *optval,
                socklen_t *optlen) {
  if (sockfd == afl_sock){
    // QUIC-Fuzz ADDED HERE
    // we return a hardcoded value for these instead of assert?
    if(optname == SO_SNDBUF){
      *((int *)optval) = so_send_buf;
      return 0;
    }else if(optname == SO_RCVBUF){
      *((int *)optval) = so_receive_buf;
      return 0;
    }else{
      assert(false); // we set assert to know there is other getsockname opt when testing other target
    }
  }

  return syscall(SYS_getsockopt, sockfd, level, optname, optval, optlen);
}

int isetsockopt(int sockfd, int level, int optname, const void *optval,
                socklen_t optlen) {
  if (sockfd == afl_sock){
    pthread_mutex_lock(&lock);

    // remember what cmsg is requested
    if(level == IPPROTO_IPV6 && (optname == IPV6_RECVPKTINFO || optname == IPV6_PKTINFO)){
      require_ipv6_pktinfo = 1;
    }else if(level == IPPROTO_IP && optname == IP_PKTINFO){
      require_ip_pktinfo = 1;
    }else if(level == IPPROTO_IPV6 && optname == IPV6_RECVTCLASS){
      require_ipv6_tclass = 1;
    }else if(level == IPPROTO_IP && optname == IP_RECVTOS){
      require_ip_tos = 1; 
    }

    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "SETSOCKOPT noww\n");
    // fclose(file);

    pthread_mutex_unlock(&lock);
    return 0; // TODO: Will this create false issues? e.g. what if a getsockopt?
  }

  // if it is UDP_GRO, we pretend that we does not support it.
  // if(level == SOL_UDP && optname == UDP_GRO){
    // if(*(int*)optval == 1){
    //   errno = ENOPROTOOPT;
    //   return -1;
    // }{
      // return 0;
    // }
  // }

  // return 0;
  return real_syscall(SYS_setsockopt, sockfd, level, optname, (long)optval,
                      optlen, 0);
}

int iaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (sockfd == target_listen_sock) {
    // TODO: we only support 1 accept.
    // dprintf(2, "Accept in: fd: %d cs: %d\n", sockfd, cs);
    assert(cs == NoAcceptYet);
    cs = Accepted;

    // dprintf(2, "Accept out: fd: %d cs: %d\n", sockfd, cs);
    return afl_sock;
  }
  // Note: Some targets might erroneously block in an accept and hang under afl.
  return real_syscall(SYS_accept4, sockfd, (long)addr, (long)addrlen,
                      SOCK_NONBLOCK, 0, 0);
}

int iaccept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  if (sockfd == target_listen_sock) {
    return iaccept(sockfd, 0, 0);
  }
  return syscall(SYS_accept4, sockfd, addr, addrlen, flags);
}

int igetsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  if (sockfd == afl_sock) {
    sockfd = target_listen_sock;
  }
  return syscall(SYS_getsockname, sockfd, addr, addrlen);
}

int igetpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  assert(sockfd != target_listen_sock);
  if (sockfd == afl_sock) {
    int rc = syscall(SYS_getsockname, target_listen_sock, addr, addrlen);
    assert(rc == 0);
    ((struct sockaddr_in *)addr)->sin_port = htons(RANDOM_PEER_ACCEPT_PORT);
    return 0;
  }
  return syscall(SYS_getpeername, sockfd, addr, addrlen);
}

int iconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  char logpath[] = "/dev/log";
  if ((addr->sa_family == AF_UNIX) &&
      (strncmp(((struct sockaddr_un *)addr)->sun_path, logpath,
               sizeof(logpath)) == 0)) {
#ifdef SF_STDIO
    target_log_sock = sockfd;
    return 0;
#else
    return real_syscall(SYS_connect, sockfd, (long)addr, addrlen, 0, 0, 0);
#endif // SF_STDIO
  }
  // dprintf(2, "Trying to connect. We will refuse\n");
  errno = ECONNREFUSED;
  return -1;
}

ssize_t isendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen) {
  if (sockfd == afl_sock) {
    pthread_mutex_lock(&lock);

    notify_a_send();
    long rc = real_syscall(SYS_sendto, sockfd, (long)buf, len, flags,
                           (long)dest_addr, addrlen);

    // if the server has a respond, means fuzzer can send the next input.
    is_server_send_now = 0;

    pthread_mutex_unlock(&lock);
    return rc;
  }
  return real_syscall(SYS_sendto, sockfd, (long)buf, len, flags,
                      (long)dest_addr, addrlen);
}

ssize_t isendmsg(int sockfd, const struct msghdr *msg, int flags) {
  // QUIC-Fuzz ADDED HERE
  if (sockfd == afl_sock) {
    pthread_mutex_lock(&lock);

    notify_a_send();
    long rc = real_syscall(SYS_sendmsg, sockfd, (long)msg, flags, 0, 0, 0);

    // if the server has a respond, means fuzzer can send the next input.
    is_server_send_now = 0;

    pthread_mutex_unlock(&lock);
    return rc;
  }

  // assert(sockfd != afl_sock);
  return real_syscall(SYS_sendmsg, sockfd, (long)msg, flags, 0, 0, 0);
}

int isendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
              int flags) {
  // TODO: support in the future
  // QUIC-Fuzz ADDED HERE
  if (sockfd == afl_sock) {
    pthread_mutex_lock(&lock);

    notify_a_send();
    long rc = real_syscall(SYS_sendmmsg, sockfd, (long)msgvec, vlen, flags, 0, 0);

    // if the server has a respond, means fuzzer can send the next input.
    is_server_send_now = 0;

    pthread_mutex_unlock(&lock);
    return rc;
  }
  
  // assert(sockfd != afl_sock);
  return real_syscall(SYS_sendmmsg, sockfd, (long)msgvec, vlen, flags, 0, 0);
}

ssize_t irecvfrom(int sockfd, void *buf, size_t len, int flags,
                  struct sockaddr *src_addr, socklen_t *addrlen) {
  // QUIC-Fuzz EDITED HERE
  if (sockfd == afl_sock) {
    if (pending_buf) {
      size_t bounded_len = len;
      assert(maxidx > idx);
      if (len > maxidx - idx)
        bounded_len = maxidx - idx;

      // fill the source address, source address length
      *addrlen = fill_addr_name((void *)src_addr);
      
      memcpy(buf, &tmpbuf[idx], bounded_len);

      // increase the idx when the target is not peeking
      if(!(flags & MSG_PEEK)){
        idx += bounded_len;
      }

      // once this input is completely consumed by the server, we give the server a chance to respond.
      if (idx >= maxidx) {
        pending_buf = false;
        idx = 0;
        maxidx = 0;

        pthread_mutex_lock(&lock);
        is_server_send_now = 1;
        server_receive_skip_count = 0;
        pthread_mutex_unlock(&lock);
      }

      return bounded_len;
    }

    pthread_mutex_lock(&lock);
    // after the fuzzer send each input, we give the server a chance to respond.
    // if the server does not responds for sometimes, we let the fuzzer send the next input.
    if(!is_server_send_now || server_receive_skip_count >= MAX_SERVER_RECV_SKIP){
      notify_a_recv();

      memset(tmpbuf, 0, sizeof(tmpbuf));

      // we need to (at least) handle the case when the target is using MSG_PEEK, MSG_TRUNC, MSG_WAITALL
      flags &= ~MSG_TRUNC; // do not truncate the input
      flags &= ~MSG_WAITALL; // do not wait for all
      int pk_buf = flags & MSG_PEEK;
      flags &= ~MSG_PEEK; // we simulate the peek using pending_buf ourselves

      long rc = real_syscall(SYS_recvfrom, sockfd, (long)tmpbuf, sizeof(tmpbuf),
                            flags, 0, 0);
      
      if (rc == -EINTR || rc < 0) {
        pthread_mutex_unlock(&lock);
        return rc;
      } else if (rc == 0) {
        // TODO: Emulate SIGTERM
        syscall(SYS_exit_group, 0);
      }
      assert(rc <= sizeof(tmpbuf));

      if(pk_buf){
        // target is peeking, so idx will be 0 in the next recv
        pending_buf = true;
        maxidx = rc;
        idx = 0;

        if(len < rc){
          rc = len;
        }
      }else if(len < rc){
        pending_buf = true;
        maxidx = rc;
        idx = len;
        rc = len;
      }

      // fill the source address, source address length
      *addrlen = fill_addr_name((void *)src_addr);

      memcpy(buf, tmpbuf, rc);

      // give server a chance to respond before sending the next input.
      if(!pending_buf){
        is_server_send_now = 1;
        server_receive_skip_count = 0;
      }

      pthread_mutex_unlock(&lock);
      return rc;
    }else{
      server_receive_skip_count += 1;
      pthread_mutex_unlock(&lock);
      return skip_recv_ret_val;
    }
  }

  return real_syscall(SYS_recvfrom, sockfd, (long)buf, len, flags,
                      (long)src_addr, (long)addrlen);
}

ssize_t irecvmsg(int sockfd, struct msghdr *msg, int flags) {
  // QUIC-Fuzz ADDED HERE
  if(sockfd == afl_sock){
    if(pending_buf){
      size_t bounded_len = msg->msg_iov[0].iov_len;
      assert(maxidx > idx);

      if (msg->msg_iov[0].iov_len > maxidx -idx){
        bounded_len = maxidx -idx;
      }

      // fill the source address, source address length
      msg->msg_namelen = fill_addr_name(msg->msg_name);
      
      // copy the buffer and buffer len
      memcpy(msg->msg_iov[0].iov_base, tmp_msg_buf + idx, bounded_len);
      msg->msg_iov[0].iov_len = bounded_len;

      // fill the control buffer and control buffer len
      fill_cmsg(msg);
      
     // increase the idx when the target is not peeking
      if(!(flags & MSG_PEEK)){
        idx += bounded_len;
      }

      // once this input is completely consumed by the server, we give the server a chance to respond.
      if (idx >= maxidx) {
        pending_buf = false;
        idx = 0;
        maxidx = 0;

        pthread_mutex_lock(&lock);
        is_server_send_now = 1;
        server_receive_skip_count = 0;
        pthread_mutex_unlock(&lock);
      }

      return bounded_len;
    }

    pthread_mutex_lock(&lock);
    // after the fuzzer send each input, we give the server a chance to respond.
    // if the server does not responds for sometimes, we let the fuzzer send the next input.
    if(!is_server_send_now || server_receive_skip_count >= MAX_SERVER_RECV_SKIP){
      notify_a_recv();

      // reset the tmp_msg_buf before recv when there is no pending
      memset(tmp_msg_buf, 0, sizeof(tmp_msg_buf));

      // we need to (at least) handle the case when the target is using MSG_PEEK, MSG_TRUNC, MSG_WAITALL
      flags &= ~MSG_TRUNC; // do not truncate the input
      flags &= ~MSG_WAITALL; // do not wait for all
      int pk_buf = flags & MSG_PEEK;
      flags &= ~MSG_PEEK; // we simulate the peek using pending_buf ourselves

      // we use recvfrom to get the input and fill into msghdr later
      long rc = real_syscall(SYS_recvfrom, sockfd, (long)tmp_msg_buf, sizeof(tmp_msg_buf), flags, 0, 0);

      if (rc == -EINTR || rc < 0) {
        pthread_mutex_unlock(&lock);
        return rc;
      } else if (rc == 0){
        // TODO: Emulate SIGTERM
        syscall(SYS_exit_group, 0);
      }
      assert(rc <= sizeof(tmp_msg_buf));

      if(pk_buf){
        // target is peeking, so idx will be 0 in the next recv
        pending_buf = true;
        maxidx = rc;
        idx = 0;

        if(msg->msg_iov[0].iov_len < rc){
          rc = msg->msg_iov[0].iov_len;
        }
      }else if(msg->msg_iov[0].iov_len < rc){
        pending_buf = true;
        maxidx = rc;
        idx = msg->msg_iov[0].iov_len;
        rc = msg->msg_iov[0].iov_len;
      }

      // fill the source address, source address length
      msg->msg_namelen = fill_addr_name(msg->msg_name);
      
      // copy the buffer and buffer len
      memcpy(msg->msg_iov[0].iov_base, tmp_msg_buf, rc);
      msg->msg_iov[0].iov_len = rc;

      // fill the control buffer and control buffer len
      fill_cmsg(msg);

      // give server a chance to respond before sending the next input.
      if(!pending_buf){
        is_server_send_now = 1;
        server_receive_skip_count = 0;
      }

      pthread_mutex_unlock(&lock);
      return rc;
    }else{
      server_receive_skip_count += 1;
      pthread_mutex_unlock(&lock);
      return skip_recv_ret_val;
    } 
  }

  // assert(sockfd != afl_sock);
  return real_syscall(SYS_recvmsg, sockfd, (long)msg, flags, 0, 0, 0);
}

int irecvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags,
              struct timespec *timeout) {
  // QUIC-Fuzz ADDED HERE
  // we assume there is only one msghdr in the msgvec
  if(sockfd == afl_sock){
    if(pending_buf){
      size_t bounded_len = msgvec[0].msg_hdr.msg_iov[0].iov_len;
      assert(maxidx > idx);

      if (msgvec[0].msg_hdr.msg_iov[0].iov_len > maxidx -idx){
        bounded_len = maxidx -idx;
      }

      msgvec[0].msg_len = bounded_len;

      // fill the source address, source address length
      msgvec[0].msg_hdr.msg_namelen = fill_addr_name(msgvec[0].msg_hdr.msg_name);
      
      // copy the buffer and buffer len
      memcpy(msgvec[0].msg_hdr.msg_iov[0].iov_base, tmp_msg_buf + idx, bounded_len);
      msgvec[0].msg_hdr.msg_iov[0].iov_len = bounded_len;

      // fill the control buffer and control buffer len
      fill_cmsg(&(msgvec[0].msg_hdr));

      // increase the idx when the target is not peeking
      if(!(flags & MSG_PEEK)){
        idx += bounded_len;
      }

      // once this input is completely consumed by the server, we give the server a chance to respond.
      if (idx >= maxidx) {
        pending_buf = false;
        idx = 0;
        maxidx = 0;

        pthread_mutex_lock(&lock);
        is_server_send_now = 1;
        server_receive_skip_count = 0;
        pthread_mutex_unlock(&lock);
      }

      return 1;
    }

    pthread_mutex_lock(&lock);
    // after the fuzzer send each input, we give the server a chance to respond.
    // if the server does not responds for sometimes, we let the fuzzer send the next input.
    if(!is_server_send_now || server_receive_skip_count >= MAX_SERVER_RECV_SKIP){
      notify_a_recv();

      // reset the tmp_msg before recv when there is no pending
      memset(tmp_msg_buf, 0, sizeof(tmp_msg_buf));

      // we need to (at least) handle the case when the target is using MSG_PEEK, MSG_TRUNC, MSG_WAITALL
      flags &= ~MSG_TRUNC; // do not truncate the input
      flags &= ~MSG_WAITALL; // do not wait for all
      int pk_buf = flags & MSG_PEEK;
      flags &= ~MSG_PEEK; // we simulate the peek here ourselves

      // we use recvfrom to get the input and fill into msghdr later
      long rc = real_syscall(SYS_recvfrom, sockfd, (long)tmp_msg_buf, sizeof(tmp_msg_buf), flags, 0, 0);

      if (rc == -EINTR || rc < 0) {
        pthread_mutex_unlock(&lock);
        return rc;
      } else if (rc == 0){
        // TODO: Emulate SIGTERM
        syscall(SYS_exit_group, 0);
      }
      assert(rc <= sizeof(tmp_msg_buf));

      if(pk_buf){
        // target is peeking, so idx will be 0 in the next recv
        pending_buf = true;
        maxidx = rc;
        idx = 0;

        if(msgvec[0].msg_hdr.msg_iov[0].iov_len < rc){
          rc = msgvec[0].msg_hdr.msg_iov[0].iov_len;
        }
      }else if(msgvec[0].msg_hdr.msg_iov[0].iov_len < rc){
        // leftover data
        pending_buf = true;
        maxidx = rc;
        idx = msgvec[0].msg_hdr.msg_iov[0].iov_len;
        rc = msgvec[0].msg_hdr.msg_iov[0].iov_len;
      }

      msgvec[0].msg_len = rc;

      // fill the source address, source address length
      msgvec[0].msg_hdr.msg_namelen = fill_addr_name(msgvec[0].msg_hdr.msg_name);

      // copy the buffer and buffer len
      memcpy(msgvec[0].msg_hdr.msg_iov[0].iov_base, tmp_msg_buf, rc);
      msgvec[0].msg_hdr.msg_iov[0].iov_len = rc;

      // fill the control buffer and control buffer len
      fill_cmsg(&(msgvec[0].msg_hdr));

      // give server a chance to respond before sending the next input.
      if(!pending_buf){
        is_server_send_now = 1;
        server_receive_skip_count = 0;
      }

      pthread_mutex_unlock(&lock);
      return 1; // we assume there is only one msghdr in the msgvec
    }else{
      server_receive_skip_count += 1;
      // errno = EWOULDBLOCK;
      pthread_mutex_unlock(&lock);
      return skip_recv_ret_val;
    } 
  }

  // assert(sockfd != afl_sock);
  return real_syscall(SYS_recvmmsg, sockfd, (long)msgvec, vlen, flags, 0, 0);
}

int ishutdown(int sockfd, int how) {
  if (sockfd == afl_sock || sockfd == AFL_CTL_SOCKET ||
      sockfd == FORKSRV_FD_1 || sockfd == FORKSRV_FD_2) {
    return 0;
  }
  return syscall(SYS_shutdown, sockfd, how);
}

int ifcntl(int fd, int cmd, int arg) {
  // This should never happen. The target should know anything about this fd.
  assert(fd != AFL_CTL_SOCKET);
  if (fd == afl_sock) {
    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "fcntl command is %d with %d\n", cmd, arg);
    // fclose(file);
    // TODO: This needs investigation
    return 0;
  }
  return syscall(SYS_fcntl, fd, cmd, arg);
}

int iselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
            struct timeval *timeout) {
  // TODO: We only support reading FDs

  if (target_listen_sock >= 0 && FD_ISSET(target_listen_sock, readfds)) {
    // dprintf(2, "I select 1 %d!\n", cs);
    if (cs == NoAcceptYet) {
      // dprintf(2, "I select 1a!\n");
      FD_CLR(target_listen_sock, readfds);

      struct timeval to = {0}; // Don't wait
      long rc = syscall(SYS_select, nfds, readfds, writefds, exceptfds, &to);

      if (rc == 0) {
        FD_SET(target_listen_sock, readfds);
        rc++;
      }

      return rc;
    } else if (cs == Done) {
      // TODO: Emulate SIGTERM
      syscall(SYS_exit_group, 0);
    } else {
      // dprintf(2, "I select 1b!\n");
      FD_CLR(target_listen_sock, readfds);
    }
  }

  if (FD_ISSET(afl_sock, readfds)) {
    // dprintf(2, "I select 2!\n");
    if (cs == Accepted) {
      FD_CLR(afl_sock, readfds);

      struct timeval to = {0}; // Don't wait
      long rc = syscall(SYS_select, nfds, readfds, writefds, exceptfds, &to);

      FD_SET(afl_sock, readfds);

      return rc + 1;
    } else {
      FD_CLR(afl_sock, readfds);
    }
  }

  return syscall(SYS_select, nfds, readfds, writefds, exceptfds, timeout);
}

static long fd_isset(int fd, struct pollfd *fds, nfds_t nfds) {
  for (nfds_t i = 0; i < nfds; i++) {
      // FILE *file= fopen("output.txt", "a");
      // fprintf(file, "server fd is %d, matching fd is %d\n", fds[i].fd, fd);
      // fclose(file);
    if (fd == fds[i].fd) {
      return i;
    }
  }
  return -1;
}

int ipoll(struct pollfd *fds, nfds_t nfds, int timeout) {
  long pos = -1;

  if ((pos = fd_isset(target_listen_sock, fds, nfds)) != -1) {
    if (cs == NoAcceptYet) {
      // dprintf(2, "Poll target_listen_sock NoAcceptYet pos: %ld\n", pos);

      // Skip target_listen_sock.
      fds[pos].fd = -1;

      // timeout = 0, don't wait.
      long rc = real_syscall(SYS_poll, (long)fds, nfds, 0, 0, 0, 0);

      // Set target_listen_sock as ready to accept a connection.
      fds[pos].fd = target_listen_sock;
      assert(fds[pos].events == POLLIN);
      fds[pos].revents = POLLIN;

      return rc + 1;
    } else if (cs == Done) {
      // TODO: Emulate SIGTERM
      sigset_t signal_set;
      sigemptyset(&signal_set);
      sigaddset(&signal_set, SIGTERM);
      sigprocmask(SIG_BLOCK, &signal_set, NULL);

      pid_t wpid;
      int status = 0;
      do {
        wpid = wait(&status);
        if (wpid <= 0)
          continue;

        if (WIFSIGNALED(status)) {
          if (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGILL) {
            raise(WTERMSIG(status));
          }
        }
      } while (wpid > 0);

      real_syscall(SYS_exit_group, 0, 0, 0, 0, 0, 0);
    } else {
      // dprintf(2, "Poll target_listen_sock Accepted\n");
      fds[pos].fd = -1;
      long rc = real_syscall(SYS_poll, (long)fds, nfds, 0, 0, 0, 0);
      fds[pos].fd = target_listen_sock;
      return rc;
    }
  }

  if ((pos = fd_isset(afl_sock, fds, nfds)) != -1) {
    if (cs == Accepted) {
      // dprintf(2, "Poll afl_sock Accepted\n");

      // Skip afl_sock.
      fds[pos].fd = -1;

      // timeout = 0, don't wait.
      long rc = real_syscall(SYS_poll, (long)fds, nfds, 0, 0, 0, 0);

      // Set afl_sock as ready to accept a connection.
      fds[pos].fd = afl_sock;
      // QUIC-Fuzz ADDED HERE
      // this only handle POLLIN, and will fail when target ask more than that
      // do we need to respond other revent other than POLLIN?
      // assert(fds[pos].events == POLLIN);

      // QUIC-Fuzz ADDED HERE
      // better way to handle when is ready to read or write?
      pthread_mutex_lock(&lock);
      if(fds[pos].events & POLLIN && !is_server_send_now){
        fds[pos].revents = POLLIN;
      }else if(fds[pos].events & POLLOUT && is_server_send_now){
        fds[pos].revents = POLLOUT;
      }else{
        fds[pos].revents = POLLIN | POLLOUT;
      }
      pthread_mutex_unlock(&lock);

      return rc + 1;
    } else {
      fds[pos].fd = -1;
      long rc = real_syscall(SYS_poll, (long)fds, nfds, 0, 0, 0, 0);
      fds[pos].fd = afl_sock;
      return rc;
    }
  }

  return real_syscall(SYS_poll, (long)fds, nfds, timeout, 0, 0, 0);
}

// QUIC-Fuzz ADDED HERE
int iepoll_create1(int flags) {
  int rc = real_syscall(SYS_epoll_create1, flags, 0, 0, 0, 0, 0);

  // FILE *file= fopen("output.txt", "a");
  // fprintf(file, "epoll_create flag is %d and new fd is %d\n", flags, rc);
  // fclose(file);

  if(epoll_sock == -1){
    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "Remember this epoll socket\n");
    // fclose(file);
    epoll_sock = rc;
  }

  return rc;
}

// QUIC-Fuzz ADDED HERE
int iepoll_create(int size) {
  int rc = real_syscall(SYS_epoll_create, size, 0, 0, 0, 0, 0);

  if(epoll_sock == -1){
    epoll_sock = rc;
  }

  return rc;
}

// QUIC-Fuzz ADDED HERE
int iepoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  // FILE *file= fopen("output.txt", "a");
  // if(event == NULL){
  //   fprintf(file, "resgistering NULL event\n");
  // }else{
  //   fprintf(file, "resgistering %d fd on %d epfd for %d\n", fd, epfd, op);
  // }
  // fclose(file);

  // we control and decide when afl_sock is ready ourselves
  // what if target want to delete afl_sock from epoll?
  if(epfd == epoll_sock && fd == afl_sock && event != NULL){
    pthread_mutex_lock(&lock);
    afl_sock_event.data = event->data;
    afl_sock_event.events = event->events;

    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "resgistering %d fd on %d epfd to %d operation for %d events\n", fd, epfd, op, event->events);
    // fclose(file);

    pthread_mutex_unlock(&lock);

    return 0;
  }

  return real_syscall(SYS_epoll_ctl, epfd, op, fd, (long)event, 0, 0);
}

// QUIC-Fuzz ADDED HERE
int iepoll_wait(int epfd, struct epoll_event *event, int maxevents, int timeout) {
  // FILE *file= fopen("output.txt", "a");
  // fprintf(file, "epoll_sock is %d; epfd is %d; afl_sock is %d; afl_sock_event.data.fd is %d;\n", epoll_sock, epfd, afl_sock, afl_sock_event.data.fd);
  // fclose(file);

  // if(epoll_sock == epfd && afl_sock_event.data.fd == afl_sock && event != NULL){
  pthread_mutex_lock(&lock);
  if(epoll_sock == epfd && afl_sock_event.data.u64 != 0 && event != NULL){
    int rc = 0;

    if(maxevents > 1){
      rc = real_syscall(SYS_epoll_wait, epfd, (long)&event[1], maxevents-1, 0, 0, 0);
    }

    if(rc == -1){
      pthread_mutex_unlock(&lock);
      return rc;
    }

    // hardcode the EPOLLIN event everytime
    event[0].data = afl_sock_event.data;
    event[0].events = afl_sock_event.events;

    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "RECVMMSG is readyy nowww with is_ipv6=%d, require_ip_pktinfo=%d, require_ipv6_pktinfo=%d, require_ip_tos=%d, require_ipv6_tclass=%d\n", is_ipv6, require_ip_pktinfo, require_ipv6_pktinfo, require_ip_tos, require_ipv6_tclass);
    // fclose(file);

    pthread_mutex_unlock(&lock);
    return rc + 1;
  }

  pthread_mutex_unlock(&lock);
  // no waiting (timeout == 0)
  return real_syscall(SYS_epoll_wait, epfd, (long)event, maxevents, 0, 0, 0);
}

// Common to FS and Net

ssize_t iread(int fd, void *buf, size_t count) {
  if (fd == afl_sock) {
    if (pending_buf) {
      // dprintf(2, "read in buff: %ld %ld %ld\n", idx, maxidx, count);
      size_t bounded_len = count;
      assert(maxidx > idx);
      if (count > maxidx - idx)
        bounded_len = maxidx - idx;

      memcpy(buf, &tmpbuf[idx], bounded_len);
      idx += bounded_len;

      if (idx >= maxidx) {
        pending_buf = false;
        idx = 0;
        maxidx = 0;
      }

      // dprintf(2, "read out buff: %ld %ld\n", bounded_len, idx);
      return bounded_len;
    }

    pthread_mutex_lock(&lock);

    notify_a_recv();

    memset(tmpbuf, 0, sizeof(tmpbuf));
    long rc = real_syscall(SYS_read, fd, (long)tmpbuf, sizeof(tmpbuf), 0, 0, 0);
    if (rc == -EINTR || rc < 0) {
      pthread_mutex_unlock(&lock);
      return rc;
    } else if (rc == 0) {
      // TODO: Emulate SIGTERM
      syscall(SYS_exit_group, 0);
    }
    assert(rc < sizeof(tmpbuf));

    if (count < rc) {
      pending_buf = true;
      maxidx = rc;
      idx = count;
      rc = count;
    }

    memcpy(buf, tmpbuf, rc);

    pthread_mutex_unlock(&lock);
    // dprintf(2, "read out: count %ld maxidx %ld\n", count, maxidx);
    return rc;
  }
  return real_syscall(SYS_read, fd, (long)buf, count, 0, 0, 0);
}

ssize_t iwrite(int fd, const void *buf, size_t count) {
  if (fd == afl_sock) {
    pthread_mutex_lock(&lock);

    notify_a_send();
    long rc = real_syscall(SYS_write, fd, (long)buf, count, 0, 0, 0);

    pthread_mutex_unlock(&lock);

    return rc;
#ifdef SF_STDIO
  } else if (fd == STDOUT_FILENO || fd == STDERR_FILENO ||
             fd == target_log_sock) {
    return count;
#endif // SF_STDIO
  }
  return real_syscall(SYS_write, fd, (long)buf, count, 0, 0, 0);
}

// Close is used in both networking and files.
int iclose(int fd) {
  if (fd == afl_sock) {
    pending_buf = false;
    if (cs == Accepted)
      cs = Done;
    return 0;
  } else if (fd == AFL_CTL_SOCKET || fd == FORKSRV_FD_1 || fd == FORKSRV_FD_2) {
    return 0;
#ifdef SF_MEMFS
  } else if (mem_fds_open[fd] == true) {
    lseek(fd, 0, SEEK_SET);
    mem_fds_open[fd] = false;
    return 0;
#endif // SF_MEMFS
  }
  return syscall(SYS_close, fd);
}

#ifdef SF_SLEEP
int inanosleep(const struct timespec *req, struct timespec *rem) {
  // TODO: This should be a 'return real_syscall(...);'.
  nanosleep((const struct timespec[]){{0, 1L}}, NULL);
  return 0;
}
int iclock_nanosleep(clockid_t clockid, int flags,
                     const struct timespec *request, struct timespec *remain) {
  clock_nanosleep(CLOCK_REALTIME, 0, (const struct timespec[]){{0, 1L}}, NULL);
  return 0;
}
#endif // SF_SLEEP

// static int cpus[8] = {0};

long number_of_processors = 0;
atomic_long last_cpu_used = 0;

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {

#ifndef SF_SMARTDEFER
  afl_manual_init();
#endif // SF_SMARTDEFER

  // if(sc_no != SYS_read && sc_no != SYS_write && sc_no != SYS_close && sc_no != SYS_openat && sc_no != SYS_fstat && sc_no != SYS_lseek && sc_no != SYS_stat){
    // FILE *file= fopen("output.txt", "a");
    // fprintf(file, "Capture systemcall %ld\n", sc_no);
    // fclose(file);
  // }

  // TODO: Switch to a switch
  if (sc_no == SYS_clone) {
    // We are about to clone/fork, we should defer the forkserver here. We
    // currently cannot defer after a clone/fork as it requires green threading
    // or thread restoration.
    // TODO: Compatibility with target's manual call to __afl_manual_init().
#ifdef SF_SMARTDEFER
    afl_manual_init();
#endif // SF_SMARTDEFER

    if (arg2 != 0) { // clone for threads
      void *ret_addr = get_syscall_return_address(wrapper_sp);
      long child_pid = clone_syscall(arg1, (void *)arg2, (void *)arg3,
                                     (void *)arg4, arg5, ret_addr, NULL);

      // TODO: All the following should actually go to the child. But
      // wrapper_sp?
      cpu_set_t c;
      CPU_ZERO(&c);
      last_cpu_used++;
      CPU_SET(last_cpu_used % number_of_processors, &c);

      int rc = 0;
      // dprintf(2, "Taso: %ld", last_cpu_used % number_of_processors);
      // rc = sched_setaffinity(child_pid, sizeof(c), &c);
      assert(rc == 0);

      return child_pid;
    } else { // fork -> if (arg2 == 0)
      return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    // QUIC-Fuzz ADDED HERE
    // Shared Memory
//   }else if(sc_no == SYS_shmat){
//     // why we need to defer the forkserver here?
//     // if we dont do this, fork server will OOM...
// #ifdef SF_SMARTDEFER
//     afl_manual_init();
// #endif // SF_SMARTDEFER

//     return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
//   }else if(sc_no == SYS_brk){
//     // why we need to defer the forkserver here?
//     // if we dont do this, fork server will crash
// #ifdef SF_SMARTDEFER
//     afl_manual_init();
// #endif // SF_SMARTDEFER

//     return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);

    // MemFS

#ifdef SF_MEMFS
  } else if (sc_no == SYS_openat) {
    return iopenat(arg1, (const char *)arg2, arg3, arg4);
  } else if (sc_no == SYS_unlink) {
    return iunlink((const char *)arg1);
  } else if (sc_no == SYS_unlinkat) {
    return iunlinkat(arg1, (const char *)arg2, arg3);
  } else if (sc_no == SYS_statfs) {
    assert(false);
  } else if (sc_no == SYS_stat) {
    return i_l_stat(SYS_stat, (const char *)arg1, (struct stat *)arg2);
  } else if (sc_no == SYS_lstat) {
    return i_l_stat(SYS_lstat, (const char *)arg1, (struct stat *)arg2);
  } else if (sc_no == SYS_open) {
    assert(false);
  } else if (sc_no == SYS_fstatfs) {
    assert(false);
  } else if (sc_no == SYS_truncate) {
    assert(false);
  } else if (sc_no == SYS_fsync) {
    assert(false);
  } else if (sc_no == SYS_rename) {
    assert(false);
  } else if (sc_no == SYS_renameat) {
    assert(false);
  } else if (sc_no == SYS_renameat2) {
    assert(false);
  } else if (sc_no == SYS_creat) {
    return icreat((const char *)arg1, arg2);
  } else if (sc_no == SYS_mkdir) {
    return imkdir((const void *)arg1, arg2);
  } else if (sc_no == SYS_mkdirat) {
    assert(false);
  } else if (sc_no == SYS_rmdir) {
    return irmdir((const void *)arg1);
#endif // SF_MEMFS

    // Networking + FS

  } else if (sc_no == SYS_read) {
    return iread(arg1, (void *)arg2, arg3);
  } else if (sc_no == SYS_write) {
    return iwrite(arg1, (const void *)arg2, arg3);
  } else if (sc_no == SYS_close) {
    return iclose(arg1);

    // Networking

  } else if (sc_no == SYS_socket) {
    return isocket(arg1, arg2, arg3);
  } else if (sc_no == SYS_getsockopt) {
    return igetsockopt(arg1, arg2, arg3, (void *)arg4, (socklen_t *)arg5);
  } else if (sc_no == SYS_setsockopt) {
    return isetsockopt(arg1, arg2, arg3, (const void *)arg4, arg5);
  } else if (sc_no == SYS_accept) {
    return iaccept(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
  } else if (sc_no == SYS_accept4) {
    return iaccept4(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3, arg4);
  } else if (sc_no == SYS_getsockname) {
    return igetsockname(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
  } else if (sc_no == SYS_getpeername) {
    return igetpeername(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
  } else if (sc_no == SYS_select) {
    // GNU pth requires select
    return iselect(arg1, (fd_set *)arg2, (fd_set *)arg3, (fd_set *)arg4,
                   (struct timeval *)arg5);
  } else if (sc_no == SYS_poll) {
    return ipoll((struct pollfd *)arg1, arg2, arg3);
  } else if (sc_no == SYS_ppoll) {
    assert(false);
  } else if (sc_no == SYS_epoll_create1) {
    return iepoll_create1(arg1);
  } else if (sc_no == SYS_epoll_create) {
    return iepoll_create(arg1);
  } else if (sc_no == SYS_epoll_ctl){
    return iepoll_ctl(arg1, arg2, arg3, (struct epoll_event *)arg4);
  }else if (sc_no == SYS_epoll_wait){
    return iepoll_wait(arg1, (struct epoll_event *)arg2, arg3, arg4);
  } else if (sc_no == SYS_pselect6) {
    assert(false);
  } else if (sc_no == SYS_fcntl) {
    return ifcntl(arg1, arg2, arg3);
  } else if (sc_no == SYS_msgsnd) {
    assert(false);
  } else if (sc_no == SYS_msgrcv) {
    assert(false);
  } else if (sc_no == SYS_connect) {
    return iconnect(arg1, (struct sockaddr *)arg2, arg3);
  } else if (sc_no == SYS_sendto) {
    return isendto(arg1, (const void *)arg2, arg3, arg4,
                   (struct sockaddr *)arg5, arg6);
  } else if (sc_no == SYS_sendmsg) {
    return isendmsg(arg1, (const struct msghdr *)arg2, arg3);
  } else if (sc_no == SYS_sendmmsg) {
    return isendmmsg(arg1, (struct mmsghdr *)arg2, arg3, arg4);
  } else if (sc_no == SYS_recvfrom) {
    return irecvfrom(arg1, (void *)arg2, arg3, arg4, (struct sockaddr *)arg5,
                     (socklen_t *)arg6);
  } else if (sc_no == SYS_recvmsg) {
    return irecvmsg(arg1, (struct msghdr *)arg2, arg3);
  } else if (sc_no == SYS_recvmmsg) {
    return irecvmmsg(arg1, (struct mmsghdr *)arg2, arg3, arg4,
                     (struct timespec *)arg5);
  } else if (sc_no == SYS_shutdown) {
    return ishutdown(arg1, arg2);
  } else if (sc_no == SYS_bind) {
    return ibind(arg1, (const struct sockaddr *)arg2, arg3);

    // Misc

#ifdef SF_SLEEP
  } else if (sc_no == SYS_nanosleep) {
    return inanosleep((const struct timespec *)arg1, (struct timespec *)arg2);
  } else if (sc_no == SYS_clock_nanosleep) {
    return iclock_nanosleep(arg1, arg2, (const struct timespec *)arg3,
                            (struct timespec *)arg4);
#endif // SF_SLEEP
    // } else if (sc_no == SYS_getpid) {
    //   assert(false);
    // } else if (sc_no == SYS_gettid) {
    //   assert(false);
    // } else if (sc_no == SYS_getpgid) {
    //   assert(false);
    // } else if (sc_no == SYS_getpgrp) {
    //   assert(false);
    // } else if (sc_no == SYS_getppid) {
    //   assert(false);
  } else if (sc_no == SYS_exit) {
    // TODO: Do we need this?
    // last_cpu_used--;
    return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  } else if (sc_no == SYS_setsid) {
    // setsid and setpgid are not supported during snapfuzzing.
    assert(false);
  } else if (sc_no == SYS_setpgid) {
    assert(false);
  }

  // TODO: No forking and threading? Think of FTP server and LIST op.

  return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
}

void_void_fn actual_clock_gettime = NULL;
void_void_fn actual_getcpu = NULL;
void_void_fn actual_gettimeofday = NULL;
void_void_fn actual_time = NULL;

typedef int clock_gettime_fn(clockid_t, struct timespec *);
int handle_vdso_clock_gettime(clockid_t arg1, struct timespec *arg2) {
  return ((clock_gettime_fn *)actual_clock_gettime)(arg1, arg2);
}

// arg3 has type: struct getcpu_cache *
typedef int getcpu_fn(unsigned *, unsigned *, void *);
int handle_vdso_getcpu(unsigned *arg1, unsigned *arg2, void *arg3) {
  return ((getcpu_fn *)actual_getcpu)(arg1, arg2, arg3);
}

typedef int gettimeofday_fn(struct timeval *, struct timezone *);
int handle_vdso_gettimeofday(struct timeval *arg1, struct timezone *arg2) {
  return ((gettimeofday_fn *)actual_gettimeofday)(arg1, arg2);
}

#ifdef __x86_64__
typedef int time_fn(time_t *);
int handle_vdso_time(time_t *arg1) { return ((time_fn *)actual_time)(arg1); }
#endif // __x86_64__

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)actual_fn;
  switch (sc_no) {
  case SYS_clock_gettime:
    actual_clock_gettime = actual_fn;
    return (void_void_fn)handle_vdso_clock_gettime;
  case SYS_getcpu:
    actual_getcpu = actual_fn;
    return (void_void_fn)handle_vdso_getcpu;
  case SYS_gettimeofday:
    actual_gettimeofday = actual_fn;
    return (void_void_fn)handle_vdso_gettimeofday;
#ifdef __x86_64__
  case SYS_time:
    actual_time = actual_fn;
    return (void_void_fn)handle_vdso_time;
#endif // __x86_64__
  default:
    return (void_void_fn)NULL;
  }
}

#ifdef __NX_INTERCEPT_RDTSC
long handle_rdtsc() {
  long high, low;

  asm volatile("rdtsc;" : "=a"(low), "=d"(high) : :);

  long ret = high;
  ret <<= 32;
  ret |= low;

  return ret;
}
#endif // __NX_INTERCEPT_RDTSC

int nprocs() {
  cpu_set_t cs;
  CPU_ZERO(&cs);
  sched_getaffinity(0, sizeof(cs), &cs);
  return CPU_COUNT(&cs);
}

void sbr_init(int *argc, char **argv[], sbr_icept_reg_fn fn_icept_reg,
              sbr_icept_vdso_callback_fn *vdso_callback,
              sbr_sc_handler_fn *syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
              sbr_rdtsc_handler_fn *rdtsc_handler,
#endif
              sbr_post_load_fn *post_load) {
  (void)fn_icept_reg; // unused
  (void)post_load;    // unused

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;

#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = handle_rdtsc;
#endif

  // QUIC-Fuzz ADDED HERE
  // decide what value to return when we want to skip the target's recv/recvmsg
  if(*argc == 2){
    skip_recv_ret_val = atoi((*argv)[1]);
  }
  // (*argc)--;
  // (*argv)++;

  int rc = pthread_mutex_init(&lock, NULL);
  assert(rc == 0);
  // TODO: The following requires __GI___ctype_init with we can't in preinit.
  // number_of_processors = sysconf(_SC_NPROCESSORS_ONLN);
  number_of_processors = nprocs();
  assert(number_of_processors > 0);

#ifdef SF_MEMFS
  // Libsqlfs
  char *memdb = ":memory:";
  rc = sqlfs_open(memdb, &sqlfs);
  assert(rc);
  assert(sqlfs != 0);
#endif // SF_MEMFS

  // TODO: assert(sqlfs_close(sqlfs));

  struct stat sockstatus;
  fstat(AFL_CTL_SOCKET, &sockstatus);
  // If we are under AFL, let's handshake.
  if (S_ISSOCK(sockstatus.st_mode) == 1) {

    char msg[] = "hello from sbr";
    rc = send(AFL_CTL_SOCKET, msg, sizeof(msg), MSG_NOSIGNAL);
    assert(rc == sizeof(msg));

    char rsp[1024] = {0};
    rc = recv(AFL_CTL_SOCKET, rsp, sizeof(rsp), 0);

    char expected[] = "hello from afl";
    assert(strncmp(rsp, expected, sizeof(expected)) == 0 &&
           rc == sizeof(expected));
  } else {
    dprintf(2, "WARN: SaBRe-afl is running headless.\n");
    // TODO: This is broken!
    // Let's local debug.
    defer_done = true;
    int sbr_pair[2];

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sbr_pair) != 0) {
      perror("socketpair() failed");
      exit(EXIT_FAILURE);
    }
    if (dup2(sbr_pair[1], AFL_CTL_SOCKET) != AFL_CTL_SOCKET) {
      perror("dup2() failed");
      exit(EXIT_FAILURE);
    }
    close(sbr_pair[1]);

    dbg_sock = sbr_pair[0];

    fstat(AFL_CTL_SOCKET, &sockstatus);
    assert(S_ISSOCK(sockstatus.st_mode) == 1);
  }
}
