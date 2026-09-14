// SPDX-License-Identifier: GPL-2.0
/*
 * Fortress LSM runtime tests. Runs as /init of a QEMU initramfs built by
 * ci/qemu-test.sh, exercises the guard through real syscalls as different
 * uids, prints "FORTRESS-TESTS: PASS" (or FAIL) and powers the VM off.
 *
 * Expected files in the initramfs:
 *   /policy/good.bin    tests/kernel/policy/good.json
 *   /policy/reload.bin  tests/kernel/policy/reload.json
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECFS		"/sys/kernel/security"
#define FORTRESS	SECFS "/fortress"
#define PROFILE_10050	"ro.product.brand=google\nro.product.model=Pixel 9\n"

static int failures, checks;

static void expect(int cond, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (!cond)
		failures++;
	printf("%s ", cond ? "  ok  " : "  FAIL");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout);
}

static void die(const char *what)
{
	printf("FATAL: %s: %s\nFORTRESS-TESTS: FAIL (setup)\n", what,
	       strerror(errno));
	fflush(stdout);
	reboot(RB_POWER_OFF);
	_exit(1);
}

/* ---- environment ------------------------------------------------------ */

static void setup_mounts(void)
{
	if (mount("proc", "/proc", "proc", 0, NULL))
		die("mount proc");
	if (mount("sysfs", "/sys", "sysfs", 0, NULL))
		die("mount sysfs");
	if (mount("securityfs", SECFS, "securityfs", 0, NULL))
		die("mount securityfs");
	if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL))
		die("mount devtmpfs");
}

static void set_ifname(struct ifreq *ifr, const char *name)
{
	size_t n = strlen(name);

	if (n >= IFNAMSIZ) {
		errno = ENAMETOOLONG;
		die(name);
	}
	memset(ifr, 0, sizeof(*ifr));
	memcpy(ifr->ifr_name, name, n + 1);
}

static void if_up(int fd, const char *name)
{
	struct ifreq ifr;

	set_ifname(&ifr, name);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr))
		die("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr))
		die("SIOCSIFFLAGS");
}

static void if_addr4(int fd, const char *name, const char *addr,
		     const char *mask)
{
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;

	set_ifname(&ifr, name);
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, addr, &sin->sin_addr);
	if (ioctl(fd, SIOCSIFADDR, &ifr))
		die("SIOCSIFADDR");
	inet_pton(AF_INET, mask, &sin->sin_addr);
	if (ioctl(fd, SIOCSIFNETMASK, &ifr))
		die("SIOCSIFNETMASK");
}

/* Kernel ABI of struct in6_ifreq (linux/ipv6.h clashes with glibc). */
struct in6_ifreq_k {
	struct in6_addr addr;
	uint32_t prefixlen;
	int ifindex;
};

static void if_addr6(const char *name, const char *addr)
{
	struct in6_ifreq_k req;
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket inet6");
	memset(&req, 0, sizeof(req));
	inet_pton(AF_INET6, addr, &req.addr);
	req.prefixlen = 64;
	req.ifindex = if_nametoindex(name);
	if (ioctl(fd, SIOCSIFADDR, &req))
		die("SIOCSIFADDR inet6");
	close(fd);
}

/* Non-persistent tun: the fd is kept open for the life of the test. */
static int tun_create(const char *name)
{
	struct ifreq ifr;
	int fd = open("/dev/net/tun", O_RDWR);

	if (fd < 0)
		die("open /dev/net/tun");
	set_ifname(&ifr, name);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, &ifr))
		die("TUNSETIFF");
	return fd;
}

static void setup_network(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket inet");
	if_up(fd, "lo");
	/* "fwg0" plays the VPN tunnel, "phys0" the real Wi-Fi/LTE link. */
	tun_create("fwg0");
	tun_create("phys0");
	if_up(fd, "fwg0");
	if_up(fd, "phys0");
	if_addr4(fd, "fwg0", "10.8.0.1", "255.255.255.0");
	if_addr4(fd, "phys0", "192.168.50.1", "255.255.255.0");
	if_addr6("fwg0", "fd00:8::1");
	if_addr6("phys0", "fd00:50::1");
	close(fd);
}

/* ---- helpers ---------------------------------------------------------- */

/*
 * Fork, become @uid and run @fn. Returns fn's exit code, or -signal if
 * the child was killed (the launch gate kills with SIGKILL).
 */
static int run_as(uid_t uid, int (*fn)(void *), void *arg)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		die("fork");
	if (pid == 0) {
		if (setresgid(uid, uid, uid))
			_exit(120);
		if (setresuid(uid, uid, uid))
			_exit(121);
		_exit(fn ? fn(arg) : 0);
	}
	if (waitpid(pid, &status, 0) < 0)
		die("waitpid");
	if (WIFSIGNALED(status))
		return -WTERMSIG(status);
	return WEXITSTATUS(status);
}

static int read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -errno;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -errno;
	buf[n] = 0;
	return n;
}

static int load_policy(const char *path)
{
	static char blob[1 << 16];
	int fd, n, err = 0;

	n = read_file(path, blob, sizeof(blob));
	if (n < 0)
		die(path);
	fd = open(FORTRESS "/policy", O_WRONLY);
	if (fd < 0)
		return errno;
	if (write(fd, blob, n) != n)
		err = errno;
	close(fd);
	return err;
}

static int load_raw(const void *buf, size_t len)
{
	int fd = open(FORTRESS "/policy", O_WRONLY), err = 0;

	if (fd < 0)
		return errno;
	if (write(fd, buf, len) != (ssize_t)len)
		err = errno;
	close(fd);
	return err;
}

static int status_has(const char *line)
{
	char buf[1024];

	if (read_file(FORTRESS "/status", buf, sizeof(buf)) < 0)
		return 0;
	return strstr(buf, line) != NULL;
}

/* Value of the "<key>: <number>" line in status, or -1. */
static long status_val(const char *key)
{
	char buf[1024], *p = buf;
	size_t n = strlen(key);

	if (read_file(FORTRESS "/status", buf, sizeof(buf)) < 0)
		return -1;
	for (;;) {
		p = strstr(p, key);
		if (!p)
			return -1;
		if ((p == buf || p[-1] == '\n') && p[n] == ':')
			return strtol(p + n + 1, NULL, 10);
		p += n;
	}
}

struct udp_arg {
	int family;
	const char *dst;
};

static int fn_udp(void *p)
{
	struct udp_arg *a = p;
	struct sockaddr_storage ss;
	socklen_t sl;
	int fd;

	memset(&ss, 0, sizeof(ss));
	if (a->family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&ss;

		s->sin_family = AF_INET;
		s->sin_port = htons(9);
		inet_pton(AF_INET, a->dst, &s->sin_addr);
		sl = sizeof(*s);
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;

		s->sin6_family = AF_INET6;
		s->sin6_port = htons(9);
		inet_pton(AF_INET6, a->dst, &s->sin6_addr);
		sl = sizeof(*s);
	}
	fd = socket(a->family, SOCK_DGRAM, 0);
	if (fd < 0)
		return 110;
	if (sendto(fd, "fortress", 8, 0, (struct sockaddr *)&ss, sl) < 0)
		return errno;
	return 0;
}

static int udp(uid_t uid, int family, const char *dst)
{
	struct udp_arg a = { family, dst };

	return run_as(uid, fn_udp, &a);
}

static int fn_profile(void *p)
{
	static char buf[1 << 16];
	const char *want = p;
	int n = read_file(FORTRESS "/self/profile", buf, sizeof(buf));

	if (n < 0)
		return -n;
	return strcmp(buf, want) ? 200 : 0;
}

static int fn_open_policy(void *p)
{
	int fd = open(FORTRESS "/policy", O_WRONLY);

	(void)p;
	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int fn_load_good(void *p)
{
	(void)p;
	return load_policy("/policy/good.bin");
}

/* ---- unix socket isolation -------------------------------------------- */

static socklen_t abstract_addr(struct sockaddr_un *addr, const char *name)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strcpy(addr->sun_path + 1, name);	/* leading NUL: abstract */
	return offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name);
}

struct server {
	pid_t pid;
};

/* Start a server as @uid bound to abstract @name; returns once bound. */
static struct server start_server(uid_t uid, int type, const char *name)
{
	struct server s;
	struct sockaddr_un sa;
	int pfd[2];
	char c;

	if (pipe(pfd))
		die("pipe");
	s.pid = fork();
	if (s.pid < 0)
		die("fork");
	if (s.pid == 0) {
		socklen_t len = abstract_addr(&sa, name);
		int fd;

		close(pfd[0]);
		if (setresgid(uid, uid, uid) || setresuid(uid, uid, uid))
			_exit(1);
		fd = socket(AF_UNIX, type, 0);
		if (fd < 0 || bind(fd, (struct sockaddr *)&sa, len))
			_exit(2);
		if (type == SOCK_STREAM && listen(fd, 64))
			_exit(3);
		if (write(pfd[1], "r", 1) != 1)
			_exit(4);
		for (;;)
			pause();
	}
	close(pfd[1]);
	if (read(pfd[0], &c, 1) != 1)
		die("server did not start");
	close(pfd[0]);
	return s;
}

static void stop_server(struct server s)
{
	kill(s.pid, SIGKILL);
	waitpid(s.pid, NULL, 0);
}

static int fn_connect(void *p)
{
	struct sockaddr_un sa;
	socklen_t len = abstract_addr(&sa, p);
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return 110;
	return connect(fd, (struct sockaddr *)&sa, len) ? errno : 0;
}

static int fn_dgram(void *p)
{
	struct sockaddr_un sa;
	socklen_t len = abstract_addr(&sa, p);
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	if (fd < 0)
		return 110;
	if (sendto(fd, "x", 1, 0, (struct sockaddr *)&sa, len) < 0)
		return errno;
	return 0;
}

/* ---- identity guard --------------------------------------------------- */

static int fn_open_ro(void *p)
{
	int fd = open((const char *)p, O_RDONLY);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

static int fn_netlink_socket(void *p)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, *(const int *)p);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

/* Sends a link dump on an already open socket, e.g. an inherited one. */
static int fn_netlink_send(void *p)
{
	struct {
		struct nlmsghdr nlh;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	if (send(*(const int *)p, &req, sizeof(req), 0) < 0)
		return errno;
	return 0;
}

/* ---- test phases ------------------------------------------------------ */

static void test_unloaded(void)
{
	char buf[256];

	printf("== boot state (no policy)\n");
	expect(read_file(SECFS "/lsm", buf, sizeof(buf)) > 0 &&
	       strstr(buf, "fortress"), "fortress listed in securityfs lsm");
	expect(status_has("state: unloaded"), "status reports unloaded");
	expect(status_has("enforce: 1"), "status reports enforcing");

	expect(run_as(10050, NULL, NULL) == -SIGKILL,
	       "app uid 10050 cannot launch without policy");
	expect(run_as(90001, NULL, NULL) == -SIGKILL,
	       "isolated uid 90001 cannot launch without policy");
	expect(run_as(1000, NULL, NULL) == 0, "system uid 1000 unaffected");

	expect(udp(0, AF_INET, "192.168.50.2") == EPERM,
	       "root egress via phys0 dropped without policy");
	expect(udp(0, AF_INET, "10.8.0.2") == EPERM,
	       "root egress via fwg0 dropped without policy");
	expect(udp(0, AF_INET, "127.0.0.1") == 0, "loopback v4 allowed");
	expect(udp(0, AF_INET6, "::1") == 0, "loopback v6 allowed");
}

static void test_load(void)
{
	static const char junk[64] = "FRTPjunk";

	printf("== policy load\n");
	expect(load_raw(junk, sizeof(junk)) == EINVAL, "garbage blob rejected");
	expect(load_raw(junk, 8) == EINVAL, "short blob rejected");
	expect(status_has("state: unloaded"), "still unloaded after rejects");
	expect(status_has("load_failures: 2"), "failures counted");
	expect(load_policy("/policy/good.bin") == 0, "good policy loaded");
	expect(status_has("state: loaded") && status_has("serial: 1"),
	       "status reports serial 1");
}

static void test_gate(void)
{
	printf("== launch gate\n");
	expect(run_as(10050, NULL, NULL) == 0, "app 10050 (in policy) launches");
	expect(run_as(1010050, NULL, NULL) == 0,
	       "app 10050 of user 10 launches (appid match)");
	expect(run_as(10099, NULL, NULL) == -SIGKILL,
	       "app 10099 (not in policy) killed");
	expect(run_as(90001, NULL, NULL) == 0, "isolated 90001 launches");
	expect(run_as(20001, NULL, NULL) == 0, "sdk sandbox 20001 launches");
}

static void test_net(void)
{
	printf("== network guard\n");
	expect(udp(10050, AF_INET, "10.8.0.2") == 0, "app -> tunnel v4 ok");
	expect(udp(10050, AF_INET, "192.168.50.2") == EPERM,
	       "app -> phys v4 dropped");
	expect(udp(10050, AF_INET6, "fd00:8::2") == 0, "app -> tunnel v6 ok");
	expect(udp(10050, AF_INET6, "fd00:50::2") == EPERM,
	       "app -> phys v6 dropped");
	expect(udp(10050, AF_INET, "127.0.0.1") == 0, "app -> loopback ok");
	expect(udp(10052, AF_INET, "10.8.0.2") == EPERM,
	       "app without NET flag -> tunnel dropped");
	expect(udp(90001, AF_INET, "10.8.0.2") == EPERM,
	       "isolated -> tunnel dropped");
	expect(udp(90001, AF_INET, "127.0.0.1") == 0, "isolated -> loopback ok");
	expect(udp(1000, AF_INET, "10.8.0.2") == 0, "system -> tunnel ok");
	expect(udp(1000, AF_INET, "192.168.50.2") == EPERM,
	       "system -> phys dropped");
	expect(udp(1073, AF_INET, "192.168.50.2") == 0,
	       "exempt network_stack -> phys ok");
	expect(udp(1073, AF_INET6, "fd00:50::2") == 0,
	       "exempt network_stack -> phys v6 ok");
	expect(udp(0, AF_INET, "192.168.50.2") == EPERM, "root -> phys dropped");
}

static void test_ipc(void)
{
	struct server s;

	printf("== unix socket isolation\n");
	s = start_server(10051, SOCK_STREAM, "fortress-stream");
	expect(run_as(10050, fn_connect, "fortress-stream") == EACCES,
	       "app 10050 -> app 10051 stream denied");
	expect(run_as(10051, fn_connect, "fortress-stream") == 0,
	       "same uid stream ok");
	expect(run_as(10060, fn_connect, "fortress-stream") == 0,
	       "trusted app 10060 -> app ok");
	expect(run_as(0, fn_connect, "fortress-stream") == 0,
	       "system (root) -> app ok");
	expect(run_as(90001, fn_connect, "fortress-stream") == EACCES,
	       "isolated -> app denied");
	stop_server(s);

	s = start_server(10051, SOCK_DGRAM, "fortress-dgram");
	expect(run_as(10050, fn_dgram, "fortress-dgram") == EACCES,
	       "app 10050 -> app 10051 dgram denied");
	expect(run_as(0, fn_dgram, "fortress-dgram") == 0,
	       "system -> app dgram ok");
	stop_server(s);
}

static void test_profile_and_access(void)
{
	printf("== identity profile and policy access\n");
	expect(run_as(10050, fn_profile, PROFILE_10050) == 0,
	       "app 10050 reads its virtual identity");
	expect(run_as(10051, fn_profile, "") == ENOENT,
	       "app without profile gets ENOENT");
	expect(run_as(0, fn_profile, "") == ENOENT, "root has no profile");

	expect(run_as(10051, fn_open_policy, NULL) == EACCES,
	       "app cannot open policy for writing");
	expect(chown(FORTRESS "/policy", 1000, 1000) == 0,
	       "policy handed to AID_SYSTEM (as init.rc does)");
	expect(run_as(1000, fn_load_good, NULL) == 0,
	       "AID_SYSTEM can load policy");
	expect(run_as(10051, fn_open_policy, NULL) == EACCES,
	       "app still cannot open policy");
}

static void test_identity(void)
{
	int route = NETLINK_ROUTE, diag = NETLINK_SOCK_DIAG, fd;
	long ident0 = status_val("deny_ident");
	long netlink0 = status_val("deny_netlink");

	printf("== identity guard\n");
	expect(run_as(10050, fn_open_ro, "/proc/net/arp") == EACCES,
	       "app cannot read the ARP table");
	expect(run_as(10050, fn_open_ro, "/proc/net/tcp") == EACCES,
	       "app cannot enumerate sockets");
	expect(run_as(10050, fn_open_ro, "/proc/net/unix") == EACCES,
	       "app cannot enumerate unix sockets");
	expect(run_as(10050, fn_open_ro, "/proc/cpuinfo") == EACCES,
	       "app cannot read /proc/cpuinfo (SoC serial)");
	expect(run_as(10050, fn_open_ro, "/proc/sys/kernel/random/boot_id") ==
	       EACCES, "app cannot read boot_id");
	expect(run_as(10050, fn_open_ro, "/sys/class/net/fwg0/address") == EACCES,
	       "app cannot read an interface MAC");
	expect(run_as(10050, fn_open_ro, "/sys/class/net") == EACCES,
	       "app cannot list interfaces via sysfs");
	expect(run_as(90001, fn_open_ro, "/proc/cpuinfo") == EACCES,
	       "isolated uid is restricted the same way");

	expect(run_as(10050, fn_open_ro, "/proc/self/status") == 0,
	       "app still reads its own /proc entries");
	expect(run_as(10050, fn_open_ro, "/sys/devices/system/cpu/online") == 0,
	       "app still reads unrelated sysfs");
	expect(run_as(1000, fn_open_ro, "/proc/net/arp") == 0,
	       "system uid reads the ARP table");
	expect(run_as(1000, fn_open_ro, "/sys/class/net/fwg0/address") == 0,
	       "system uid reads an interface MAC");

	expect(run_as(10050, fn_netlink_socket, &route) == EACCES,
	       "app cannot open a NETLINK_ROUTE socket");
	expect(run_as(10050, fn_netlink_socket, &diag) == EACCES,
	       "app cannot open a NETLINK_SOCK_DIAG socket");
	expect(run_as(90001, fn_netlink_socket, &route) == EACCES,
	       "isolated uid cannot open a NETLINK_ROUTE socket");
	expect(run_as(1000, fn_netlink_socket, &route) == 0,
	       "system uid opens a NETLINK_ROUTE socket");

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	expect(fd >= 0, "root opens a NETLINK_ROUTE socket to hand down");
	expect(run_as(10050, fn_netlink_send, &fd) == EACCES,
	       "app cannot RTM_GETLINK on an inherited socket");
	expect(run_as(1000, fn_netlink_send, &fd) == 0,
	       "system uid may RTM_GETLINK on it");
	close(fd);

	/*
	 * Exact deltas, so an unexpected extra denial (over-blocking in a
	 * case expected to succeed) fails the test just as a missing one does.
	 */
	expect(status_val("deny_ident") - ident0 == 8,
	       "8 file denials counted");
	expect(status_val("deny_netlink") - netlink0 == 4,
	       "4 netlink denials counted");
}

static void test_reload(void)
{
	static char blob[1 << 16];
	int n = read_file("/policy/good.bin", blob, sizeof(blob));

	printf("== atomic reload\n");
	blob[20] ^= 0x7f;	/* corrupt n_apps */
	expect(n > 0 && load_raw(blob, n) == EINVAL, "corrupted blob rejected");
	expect(status_has("serial: 1"), "previous policy still active");
	expect(load_policy("/policy/reload.bin") == 0, "reload policy loaded");
	expect(status_has("serial: 2"), "status reports serial 2");
	expect(run_as(10050, NULL, NULL) == -SIGKILL,
	       "app 10050 removed from policy is killed");
	expect(run_as(10051, NULL, NULL) == 0, "app 10051 still launches");
}

int main(void)
{
	printf("fortress_test: starting\n");
	setup_mounts();
	setup_network();

	test_unloaded();
	test_load();
	test_gate();
	test_net();
	test_ipc();
	test_profile_and_access();
	test_identity();
	test_reload();

	if (failures)
		printf("FORTRESS-TESTS: FAIL (%d of %d)\n", failures, checks);
	else
		printf("FORTRESS-TESTS: PASS (%d checks)\n", checks);
	fflush(stdout);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
