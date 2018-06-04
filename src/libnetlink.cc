/*
 * libnetlink.c RTnetlink service routines.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *              Aart van Halteren (a.t.vanhalteren@kpn.com) - Mainly wrapping into a C++ class
 *              Mariusz Jedwabny (mariusz@jedwabny.net) - Adapt to NiceShaper
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "libnetlink.h"

#include "aux.h"
#include "logger.h"
#include "sys.h"

int
RTNetlink::rtnl_open(rtnl_handle *rth, unsigned subscriptions)
{
        socklen_t addr_len;

        memset(rth, 0, sizeof(struct rtnl_handle));

        rth->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (rth->fd < 0) {
                log->error(52, "Cannot open netlink socket");
                return -1;
        }

        memset(&rth->local, 0, sizeof(rth->local));
        rth->local.nl_family = AF_NETLINK;
        rth->local.nl_groups = subscriptions;

        if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
                log->error(52, "Cannot bind netlink socket");
                return -1;
        }
        addr_len = sizeof(rth->local);
        if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
                log->error(52, "Cannot getsockname");
                return -1;
        }
        if (addr_len != sizeof(rth->local)) {
                log->error(52, "Wrong address length " + aux::int_to_str(addr_len));
                return -1;
        }
        if (rth->local.nl_family != AF_NETLINK) {
                log->error(52, "Wrong address family " + aux::int_to_str(rth->local.nl_family));
                return -1;
        }
        rth->seq = time(NULL);
        return 0;
}

void
RTNetlink::rtnl_close(rtnl_handle *rth)
{
        close(rth->fd);
        rth->fd = -1;
}

int
RTNetlink::rtnl_wilddump_request(rtnl_handle *rth, int family, int type)
{
        struct {
                struct nlmsghdr nlh;
                struct rtgenmsg g;
        } req;
        struct sockaddr_nl nladdr;

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = type;
        req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
        req.nlh.nlmsg_pid = 0;
        req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
        req.g.rtgen_family = family;

        return sendto(rth->fd, (void*)&req, sizeof(req), 0, (struct sockaddr*)&nladdr, sizeof(nladdr));
}

int
RTNetlink::rtnl_send(struct rtnl_handle *rth, char *buf, int len)
{
        struct sockaddr_nl nladdr;

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        return sendto(rth->fd, buf, len, 0, (struct sockaddr*)&nladdr, sizeof(nladdr));
}

int
RTNetlink::rtnl_dump_request(rtnl_handle *rth, int type, void *req, size_t len)
{
        struct nlmsghdr nlh;
        struct sockaddr_nl nladdr;
        struct iovec iov[2] = { { &nlh, sizeof(nlh) }, { req, len } };
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                iov,    2,
                NULL,   0,
                0
        };

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        nlh.nlmsg_len = NLMSG_LENGTH(len);
        nlh.nlmsg_type = type;
        nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
        nlh.nlmsg_pid = 0;
        nlh.nlmsg_seq = rth->dump = ++rth->seq;

        return sendmsg(rth->fd, &msg, 0);
}

int
RTNetlink::rtnl_dump_filter(struct rtnl_handle *rth,
                     int (*filter)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
                     void *arg1,
                     int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
                     void *arg2,
                     EnumTcObjectType qos_scope_object)
{
        char    buf[8192];
        struct sockaddr_nl nladdr;
        struct iovec iov = { buf, sizeof(buf) };

        while (1) {
                int status;
                struct nlmsghdr *h;

                struct msghdr msg = {
                        (void*)&nladdr, sizeof(nladdr),
                        &iov,   1,
                        NULL,   0,
                        0
                };

                status = recvmsg(rth->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        log->error(52, "OVERRUN");
                        continue;
                }
                if (status == 0) {
                        log->error(52, "EOF on netlink");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        log->error(52, "sender address length == " + aux::int_to_str(msg.msg_namelen));
                        return -1;
                }

                h = (struct nlmsghdr*)buf;

                while (NLMSG_OK(h, (size_t)status)) {
                        int err;

                        if (h->nlmsg_pid != rth->local.nl_pid ||
                            h->nlmsg_seq != rth->dump) {
                                if (junk) {
                                        err = junk(&nladdr, h, arg2);
                                        if (err < 0)
                                                return err;
                                }
                                goto skip_it;
                        }

                        if (h->nlmsg_type == NLMSG_DONE)
                                return 0;

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                                        log->error(52, "ERROR truncated");
                                } else {
                                        errno = -err->error;
                                        log->error(52,  "RTNETLINK answers");
                                }
                                return -1;
                        }

                        // err = filter(&nladdr, h, arg1);
                        if (qos_scope_object == QOS_CLASS) err = sys->qosCheckClassesBytes(&nladdr, h);
                        else if (qos_scope_object == QOS_FILTER) err = sys->qosCheckFiltersHits(&nladdr, h);
                        else err = -1;

                        if (err < 0)
                                return err;

skip_it:
                        h = NLMSG_NEXT(h, status);
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        log->error(52, "Message truncated");
                        continue;
                }
                if (status) {
                        log->error(52, "!!!Remnant of size " + aux::int_to_str(status));
                        return -1;
                }
        }
}

int
RTNetlink::rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
              unsigned groups, struct nlmsghdr *answer,
              int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
              void *jarg)
{
        int status;
        unsigned seq;
        struct nlmsghdr *h;
        struct sockaddr_nl nladdr;
        struct iovec iov = { (void*)n, n->nlmsg_len };
        char   buf[8192];
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                &iov,   1,
                NULL,   0,
                0
        };

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = peer;
        nladdr.nl_groups = groups;

        n->nlmsg_seq = seq = ++rtnl->seq;
        if (answer == NULL)
                n->nlmsg_flags |= NLM_F_ACK;

        status = sendmsg(rtnl->fd, &msg, 0);

        if (status < 0) {
                log->error(52, "Cannot talk to rtnetlink");
                return -1;
        }

        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        while (1) {
                status = recvmsg(rtnl->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        log->error(52, "OVERRUN");
                        continue;
                }
                if (status == 0) {
                        log->error(52, "EOF on netlink");
                        return -1;
                }
                if (msg.msg_namelen != (int)sizeof(nladdr)) {
                        log->error(52, "sender address length == " + aux::int_to_str(msg.msg_namelen));
                        return -1;
                }
                for (h = (struct nlmsghdr*)buf; status >= (int)sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

                        if (l<0 || len>status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        log->error(52, "Truncated message");
                                        return -1;
                                }
                                log->error(52, "!!!malformed message: len=" + aux::int_to_str(len));
                                return -1;
                        }

                        if (h->nlmsg_pid != rtnl->local.nl_pid ||
                            h->nlmsg_seq != seq) {
                                if (junk) {
                                        err = junk(&nladdr, h, jarg);
                                        if (err < 0)
                                                return err;
                                }
                                continue;
                        }

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                                if (l < (int)sizeof(struct nlmsgerr)) {
                                        log->error(52, "ERROR truncated");
                                } else {
                                        errno = -err->error;
                                        if (errno == 0) {
                                                if (answer)
                                                        memcpy(answer, h, h->nlmsg_len);
                                                return 0;
                                        }
                                        log->error(52, "RTNETLINK answers");
                                }
                                return -1;
                        }
                        if (answer) {
                                memcpy(answer, h, h->nlmsg_len);
                                return 0;
                        }

                        log->error(52, "Unexpected reply!!!");

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        log->error(52, "Message truncated");
                        continue;
                }
                if (status) {
                        log->error(52, "!!!Remnant of size " + aux::int_to_str(status));
                        return -1;
                }
        }
}

int
RTNetlink::rtnl_listen(struct rtnl_handle *rtnl,
              int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
              void *jarg)
{
        int status;
        struct nlmsghdr *h;
        struct sockaddr_nl nladdr;
        struct iovec iov;
        char   buf[8192];
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                &iov,   1,
                NULL,   0,
                0
        };

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;


        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        while (1) {
                status = recvmsg(rtnl->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        log->error(52, "OVERRUN");
                        continue;
                }
                if (status == 0) {
                        log->error(52, "EOF on netlink");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        log->error(52, "Sender address length == " + aux::int_to_str(msg.msg_namelen));
                        return -1;
                }
                for (h = (struct nlmsghdr*)buf; status >= (int)sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

                        if (l<0 || len>status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        log->error(52, "Truncated message");
                                        return -1;
                                }
                                log->error(52, "!!!malformed message: len=" + aux::int_to_str(len));
                                return -1;
                        }

                        err = handler(&nladdr, h, jarg);
                        if (err < 0)
                                return err;

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        log->error(52, "Message truncated");
                        continue;
                }
                if (status) {
                        log->error(52, "!!!Remnant of size " + aux::int_to_str(status));
                        return -1;
                }
        }
}

int
RTNetlink::rtnl_ask(rtnl_handle* rtnl, struct iovec *iov, size_t iovlen,
                                struct rtnl_dialog *d, char *buf, int len)
{
        int i;
        struct nlmsghdr *n = (struct nlmsghdr *)iov[0].iov_base;
        struct sockaddr_nl nladdr;
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                iov,    iovlen,
                NULL,   0,
                0
        };

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        n->nlmsg_seq = d->seq = ++rtnl->seq;
        n->nlmsg_flags |= NLM_F_ACK|NLM_F_REQUEST;
        n->nlmsg_len = 0;

        for (i=0; i<(int)iovlen-1; i++) {
                iov[i].iov_len = NLMSG_ALIGN(iov[i].iov_len);
                n->nlmsg_len += iov[i].iov_len;
        }
        n->nlmsg_len += iov[iovlen-1].iov_len;

        d->buf = d->ptr = buf;
        d->buflen = len;
        d->curlen = 0;

        i = sendmsg(rtnl->fd, &msg, 0);
        if (i == (int)n->nlmsg_len)
                return 0;
        return -1;
}

struct nlmsghdr*
RTNetlink::rtnl_wait(rtnl_handle *rth, struct rtnl_dialog *d, int *err)
{
        int status;
        struct nlmsghdr *n;

        while (1) {
                if (d->curlen == 0) {
                        struct iovec iov = { (void*)d->buf, d->buflen };
                        struct msghdr msg = {
                                (void*)&d->peer, sizeof(d->peer),
                                &iov,   1,
                                NULL,   0,
                                0
                        };

                        status = recvmsg(rth->fd, &msg, 0);

                        if (status < 0) {
                                int s_errno = errno;
                                if (errno == EINTR)
                                        continue;
                                rtnl_flush(rth);
                                errno = s_errno;
                                *err = -1;
                                return NULL;
                        }
                        if (status == 0) {
                                log->error(52, "EOF on netlink");
                                *err = -1;
                                errno = EINVAL;
                                return NULL;
                        }
                        if (msg.msg_namelen != sizeof(d->peer)) {
                                log->error(52, "sender address length == " + aux::int_to_str(msg.msg_namelen));
                                *err = -1;
                                errno = EINVAL;
                                return NULL;
                        }
                        if (d->peer.nl_pid) {
                                log->error(52, "message from " + aux::int_to_str(d->peer.nl_pid));
                                continue;
                        }
                        d->curlen = status;
                        d->ptr = d->buf;
                }

                n = (struct nlmsghdr*)d->ptr;
                status = d->curlen;

                while ((NLMSG_OK(n, (size_t)status))) {
                        d->curlen -= NLMSG_ALIGN(n->nlmsg_len);
                        d->ptr += NLMSG_ALIGN(n->nlmsg_len);

                        if (n->nlmsg_pid != rth->local.nl_pid ||
                            n->nlmsg_seq != d->seq) {
                                /* if (rth->junk)
                                        rth->junk(&d->peer, n);
                                 */
                                goto skip_it;
                        }

                        if (n->nlmsg_type == NLMSG_DONE) {
                                *err = 0;
                                return NULL;
                        }
                        if (n->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *e = (struct nlmsgerr*)NLMSG_DATA(n);
                                if (n->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                                        log->error(52, "ERROR truncated");
                                        errno = EINVAL;
                                } else if (e->error == 0) {
                                        *err = 0;
                                        return NULL;
                                } else {
                                        errno = -e->error;
                                        log->error(52, "RTNETLINK error: " + std::string (strerror(errno)));
                                        errno = -e->error;
                                }
                                *err = -1;
                                return NULL;
                        }
                        return n;

skip_it:
                        n = NLMSG_NEXT(n, status);
                }
                d->curlen = 0;
                d->ptr = d->buf;
        }
}

/* As fast as possible flush queue.
   A part of information is lost in any case, so that
   the best that we can make now is to ignore burst
   and try to recover.
 */
void
RTNetlink::rtnl_flush(rtnl_handle *rth)
{
        char buf[8];

        while (recv(rth->fd, buf, sizeof(buf), MSG_DONTWAIT) >= 0 ||
               errno != EAGAIN)
        {
                /* NOTHING */;
    }

        sleep(1);

        while (recv(rth->fd, buf, sizeof(buf), MSG_DONTWAIT) >= 0 ||
               errno != EAGAIN)
        {
                /* NOTHING */;
    }
}

int
RTNetlink::rtnl_tell_iov(rtnl_handle *rth, struct iovec *iov, size_t iovlen)
{
        int err;
        char buf[4096];
        struct rtnl_dialog d;

        err = rtnl_ask(rth, iov, iovlen, &d, buf, sizeof(buf));
        if (err)
                return err;

        while (rtnl_wait(rth, &d, &err) != NULL)
        {
                /* NOTHING */;
        }

        return err;
}

int
RTNetlink::rtnl_tell(rtnl_handle *rth, struct nlmsghdr *n)
{
        struct iovec iov = { (void*)n, n->nlmsg_len };

        return rtnl_tell_iov(rth, &iov, 1);
}


/*int
RTNetlink::rtnl_from_file(FILE *rtnl,
              int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
              void *jarg)
{
        int status;
        struct sockaddr_nl nladdr;
        char   buf[8192];
        struct nlmsghdr *h = (struct nlmsghdr*)buf;

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;

        while (1) {
                int err, len, type;
                int l;

                status = fread(&buf, 1, sizeof(*h), rtnl);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        //fprintf(stderr, "rtnl_from_file: fread");
                        log->error(52, "rtnl_from_file: fread");
                        return -1;
                }
                if (status == 0)
                        return 0;

                len = h->nlmsg_len;
                type = h->nlmsg_type;
                l = len - sizeof(*h);

                if (l<0 || len>(int)sizeof(buf)) {
                        //fprintf(stderr, "!!!malformed message: len=%d @%lu\n", len, ftell(rtnl));
                        log->error(52, "!!!malformed message: len=" + aux::int_to_str(len) + " @" + aux::int_to_str(ftell(rtnl)));
                        return -1;
                }

                status = fread(NLMSG_DATA(h), 1, NLMSG_ALIGN(l), rtnl);

                if (status < 0) {
                        //fprintf(stderr, "rtnl_from_file: fread");
                        log->error(52, "rtnl_from_file: fread");
                        return -1;
                }
                if (status < l) {
                        //fprintf(stderr, "rtnl-from_file: truncated message\n");
                        log->error(52,  "rtnl-from_file: truncated message");
                        return -1;
                }

                err = handler(&nladdr, h, jarg);
                if (err < 0)
                        return err;
        }
}
*/

int
RTNetlink::addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
        int len = RTA_LENGTH(4);
        struct rtattr *rta;
        if ((int)NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
                return -1;
        rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
        rta->rta_type = type;
        rta->rta_len = len;
        memcpy(RTA_DATA(rta), &data, 4);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
        return 0;
}

int
RTNetlink::addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
        int len = RTA_LENGTH(alen);
        struct rtattr *rta;

        if ((int)NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
                return -1;
        rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
        rta->rta_type = type;
        rta->rta_len = len;
        memcpy(RTA_DATA(rta), data, alen);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
        return 0;
}

int
RTNetlink::rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data)
{
        int len = RTA_LENGTH(4);
        struct rtattr *subrta;

        if (RTA_ALIGN(rta->rta_len) + len > maxlen)
                return -1;
        subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
        subrta->rta_type = type;
        subrta->rta_len = len;
        memcpy(RTA_DATA(subrta), &data, 4);
        rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
        return 0;
}

int
RTNetlink::rta_addattr_l(struct rtattr *rta, int maxlen, int type, void *data, int alen)
{
        struct rtattr *subrta;
        int len = RTA_LENGTH(alen);

        if (RTA_ALIGN(rta->rta_len) + len > maxlen)
                return -1;
        subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
        subrta->rta_type = type;
        subrta->rta_len = len;
        memcpy(RTA_DATA(subrta), data, alen);
        rta->rta_len = NLMSG_ALIGN(rta->rta_len) + len;
        return 0;
}


int
RTNetlink::parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
        while (RTA_OK(rta, len)) {
                if (rta->rta_type <= max)
                        tb[rta->rta_type] = rta;
                rta = RTA_NEXT(rta,len);
        }
        if (len)
                log->error(52, "!!!Deficit " + aux::int_to_str(len) + ", rta_len=" + aux::int_to_str(rta->rta_len));
        return 0;
}
