/* The userspace half of BINDER_TYPE_FD.
 *
 * The driver cannot move a descriptor from one process to another - no KPI on
 * macOS can (doc/NABI-INTEGRATION.md, "Descriptors: the part the kernel
 * cannot do") - so it validates the object, refuses it when the receiver does
 * not accept descriptors, stamps the sender's pid into the cookie and leaves
 * the sender's descriptor number in place. This file is the broker the spec
 * describes: every nabi process connects to one rendezvous socket; a sender
 * that sees a BINDER_TYPE_FD leave in a transaction registers (pid, fd) with
 * the broker and the descriptor arrives over SCM_RIGHTS; a receiver that sees
 * one arrive asks the broker for (cookie, fd), gets the descriptor back and
 * registers it with its own fd table before the guest reads the object.
 *
 * The rendezvous lives in a runtime directory owned by the first process -
 * the instance root - created at startup by binder_broker_init() and
 * remembered in NABI_BINDER_BROKER, which fork children inherit and guest exec
 * never touches (exec rebuilds the guest's stack, not the host environment).
 * The root hosts the acceptor thread; every other process is a client.
 *
 * Ordering is safe by construction: the sender registers during the write
 * translation, which completes before the ioctl that queues the transaction,
 * so by the time the receiver's read delivers the transaction and the
 * receiver asks, the descriptor is already with the broker. A registration
 * that is never asked for - the driver refused the object, say - is a leaked
 * descriptor for as long as the broker lives; the alternative is failing the
 * transaction after the fact, which is worse.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <limits.h>

#include "noah.h"

#define BINDER_BROKER_ENV	"NABI_BINDER_BROKER"
#define BINDER_BROKER_SOCK	"broker.sock"

#define BRK_REGISTER	1u
#define BRK_REQUEST	2u

/* One wire message. REGISTER rides in a sendmsg whose cmsg carries the
 * descriptor; REQUEST carries none and its reply is another message with the
 * descriptor (or kind 0) in the cmsg. */
struct binder_broker_msg {
	uint32_t kind;
	uint32_t pid;
	uint32_t fd;
};

struct broker_entry {
	uint32_t pid;
	uint32_t fd;
	int host_fd;
	struct broker_entry *next;
};

static pthread_mutex_t broker_lock = PTHREAD_MUTEX_INITIALIZER;
static struct broker_entry *broker_entries;

static void
broker_store(uint32_t pid, uint32_t fd, int host_fd)
{
	struct broker_entry *e = malloc(sizeof *e);
	if (e == NULL) {
		close(host_fd);
		return;
	}
	e->pid = pid;
	e->fd = fd;
	e->host_fd = host_fd;
	pthread_mutex_lock(&broker_lock);
	e->next = broker_entries;
	broker_entries = e;
	pthread_mutex_unlock(&broker_lock);
}

/* The oldest registration matching the pair, handed to the requester. A
 * process sending the same descriptor twice in a row registers two entries
 * and the receiver takes them in transaction order. */
static int
broker_take(uint32_t pid, uint32_t fd)
{
	pthread_mutex_lock(&broker_lock);
	struct broker_entry **pp = &broker_entries;
	while (*pp != NULL) {
		struct broker_entry *e = *pp;
		if (e->pid == pid && e->fd == fd) {
			*pp = e->next;
			int host_fd = e->host_fd;
			free(e);
			pthread_mutex_unlock(&broker_lock);
			return host_fd;
		}
		pp = &e->next;
	}
	pthread_mutex_unlock(&broker_lock);
	return -1;
}

/* Serve one client connection until it closes: hold its registered
 * descriptors and answer its requests. */
static void *
broker_serve(void *arg)
{
	int c = (int)(intptr_t)arg;

	for (;;) {
		char cbuf[CMSG_SPACE(sizeof(int))];
		struct binder_broker_msg m;
		struct iovec iov = { &m, sizeof m };
		struct msghdr hdr;

		memset(&hdr, 0, sizeof hdr);
		hdr.msg_iov = &iov;
		hdr.msg_iovlen = 1;
		hdr.msg_control = cbuf;
		hdr.msg_controllen = sizeof cbuf;

		ssize_t n = recvmsg(c, &hdr, 0);
		if (n <= 0)
			break;
		if (n != (ssize_t)sizeof m)
			continue;		/* drop garbage, keep the connection */

		int host_fd = -1;
		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&hdr); cm != NULL;
		    cm = CMSG_NXTHDR(&hdr, cm)) {
			if (cm->cmsg_level == SOL_SOCKET &&
			    cm->cmsg_type == SCM_RIGHTS) {
				memcpy(&host_fd, CMSG_DATA(cm), sizeof host_fd);
				break;
			}
		}

		if (m.kind == BRK_REGISTER) {
			char ack = (host_fd >= 0) ? 0 : (char)-1;

			if (host_fd >= 0)
				broker_store(m.pid, m.fd, host_fd);
			send(c, &ack, 1, 0);
		} else if (m.kind == BRK_REQUEST) {
			struct binder_broker_msg resp = m;
			char cbuf2[CMSG_SPACE(sizeof(int))];

			resp.kind = 0;		/* none, unless found below */
			int f = broker_take(m.pid, m.fd);
			if (f >= 0)
				resp.kind = BRK_REQUEST;
			memset(&hdr, 0, sizeof hdr);
			iov.iov_base = &resp;
			iov.iov_len = sizeof resp;
			hdr.msg_iov = &iov;
			hdr.msg_iovlen = 1;
			if (f >= 0) {
				memset(cbuf2, 0, sizeof cbuf2);
				hdr.msg_control = cbuf2;
				hdr.msg_controllen = sizeof cbuf2;
				struct cmsghdr *cm = CMSG_FIRSTHDR(&hdr);
				cm->cmsg_level = SOL_SOCKET;
				cm->cmsg_type = SCM_RIGHTS;
				cm->cmsg_len = CMSG_LEN(sizeof(int));
				*(int *)CMSG_DATA(cm) = f;
			}
			if (sendmsg(c, &hdr, 0) < 0 && f >= 0)
				close(f);
		}
	}
	close(c);
	return NULL;
}

static void *
broker_acceptor(void *arg)
{
	int lsock = (int)(intptr_t)arg;

	for (;;) {
		int c = accept(lsock, NULL, NULL);
		if (c < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		fcntl(c, F_SETFD, FD_CLOEXEC);
		pthread_t t;
		if (pthread_create(&t, NULL, broker_serve,
		    (void *)(intptr_t)c) != 0) {
			close(c);
			continue;
		}
		pthread_detach(t);
	}
	close(lsock);
	return NULL;
}

static char broker_dir[PATH_MAX];
static char broker_path[PATH_MAX];

/* The instance root owns the runtime directory; take it away at exit. The
 * fork children never reach here - for them the env is set and this
 * function is not registered. */
static void
broker_cleanup(void)
{
	unlink(broker_path);
	rmdir(broker_dir);
}

int
binder_broker_init(void)
{
	const char *env = getenv(BINDER_BROKER_ENV);

	if (env != NULL && *env != '\0')
		return 0;		/* a fork child; the root runs the broker */

	const char *base = getenv("TMPDIR");
	if (base == NULL || *base == '\0')
		base = "/tmp";

	snprintf(broker_dir, sizeof broker_dir, "%s/msl-nabi-XXXXXX", base);
	if (mkdtemp(broker_dir) == NULL)
		return -1;

	snprintf(broker_path, sizeof broker_path, "%s/%s",
	    broker_dir, BINDER_BROKER_SOCK);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return -1;

	struct sockaddr_un sa;
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, broker_path, sizeof sa.sun_path - 1);
	if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0 ||
	    listen(s, 8) < 0) {
		close(s);
		return -1;
	}
	fcntl(s, F_SETFD, FD_CLOEXEC);

	/* Set before the acceptor starts, so a fork child never races it. */
	if (setenv(BINDER_BROKER_ENV, broker_dir, 1) != 0) {
		close(s);
		return -1;
	}

	pthread_t t;
	if (pthread_create(&t, NULL, broker_acceptor, (void *)(intptr_t)s) != 0)
		return -1;
	pthread_detach(t);
	atexit(broker_cleanup);
	return 0;
}

/* One client socket per process, opened on first use. */
static int broker_sock = -1;

static int
broker_connect(void)
{
	if (broker_sock >= 0)
		return 0;

	const char *dir = getenv(BINDER_BROKER_ENV);
	if (dir == NULL || *dir == '\0')
		return -1;

	char path[PATH_MAX];
	snprintf(path, sizeof path, "%s/%s", dir, BINDER_BROKER_SOCK);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	fcntl(s, F_SETFD, FD_CLOEXEC);

	struct sockaddr_un sa;
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, path, sizeof sa.sun_path - 1);
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
		close(s);
		return -1;
	}
	broker_sock = s;
	return 0;
}

/* The sender's half. pid is the sender's own pid - the same value the driver
 * records as the cookie - and fd its descriptor number, which is also the
 * host descriptor here, so it goes across as it is. */
int
binder_broker_register(uint32_t pid, uint32_t fd)
{
	struct binder_broker_msg m = { BRK_REGISTER, pid, fd };
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { &m, sizeof m };
	struct msghdr hdr;
	char ack;

	if (broker_connect() != 0)
		return -1;

	memset(&hdr, 0, sizeof hdr);
	memset(cbuf, 0, sizeof cbuf);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = cbuf;
	hdr.msg_controllen = sizeof cbuf;
	struct cmsghdr *cm = CMSG_FIRSTHDR(&hdr);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cm) = (int)fd;

	if (sendmsg(broker_sock, &hdr, 0) != (ssize_t)sizeof m)
		return -1;
	if (recv(broker_sock, &ack, 1, 0) != 1 || ack != 0)
		return -1;
	return 0;
}

/* The receiver's half. pid is the cookie the driver stamped - the sender's
 * pid - and fd the sender's descriptor number. Returns the descriptor, which
 * the caller registers with its own fd table, or -1. */
int
binder_broker_request(uint32_t pid, uint32_t fd)
{
	struct binder_broker_msg m = { BRK_REQUEST, pid, fd };
	struct iovec iov = { &m, sizeof m };
	struct msghdr hdr;
	char cbuf[CMSG_SPACE(sizeof(int))];

	if (broker_connect() != 0)
		return -1;

	memset(&hdr, 0, sizeof hdr);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	if (sendmsg(broker_sock, &hdr, 0) != (ssize_t)sizeof m)
		return -1;

	struct binder_broker_msg resp;
	struct iovec riov = { &resp, sizeof resp };
	memset(&hdr, 0, sizeof hdr);
	memset(cbuf, 0, sizeof cbuf);
	hdr.msg_iov = &riov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = cbuf;
	hdr.msg_controllen = sizeof cbuf;

	ssize_t n = recvmsg(broker_sock, &hdr, 0);
	if (n != (ssize_t)sizeof resp || resp.kind != BRK_REQUEST)
		return -1;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&hdr); cm != NULL;
	    cm = CMSG_NXTHDR(&hdr, cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
			int got;
			memcpy(&got, CMSG_DATA(cm), sizeof got);
			return got;
		}
	}
	return -1;
}
