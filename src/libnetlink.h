/****************************************************************************

  KOM RSVP Engine (release version 2.1)

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version
  2 of the License, or (at your option) any later version.

  Author: Aart van Halteren (a.t.vanhalteren@kpn.com)
  Date: December 2000

  Based on the TrafficControl software written by Alexey Kuznetsov (kuznet@ms2.inr.ac.ru)

*/

#ifndef __RTNetlink_H__
#define __RTNetlink_H__ 1

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#include "main.h"

#define rtnl_iov_set(a, b) (iov[ct].iov_base = (a), iov[ct].iov_len = (b), ct++)


class RTNetlink
{
  public:
        struct rtnl_handle
        {
                int                     fd;
                struct sockaddr_nl      local;
                struct sockaddr_nl      peer;
                __u32                   seq;
                __u32                   dump;
        };

        struct rtnl_dialog
        {
                struct sockaddr_nl      peer;
                char                    *buf;
                char                    *ptr;
                __u32                   seq;
                size_t                     buflen;
                size_t                     curlen;
        };

        static int rtnl_open(rtnl_handle *rth, unsigned subscriptions);
        static void rtnl_close(rtnl_handle *rth);
        static int rtnl_wilddump_request(rtnl_handle *rth, int fam, int type);
        static int rtnl_dump_request(rtnl_handle *rth, int type, void *req, size_t len);
        static int rtnl_dump_filter(rtnl_handle *rth,
                                    int (*filter)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
                                    void *arg1,
                                    int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
                                    void *arg2,
                                    EnumTcObjectType);
        static int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
                             unsigned groups,
                             struct nlmsghdr *answer,
                             int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
                             void *jarg);
        static int rtnl_send(struct rtnl_handle *rth, char *buf, int);


        static int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data);
        static int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen);
        static int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data);
        static int rta_addattr_l(struct rtattr *rta, int maxlen, int type, void *data, int alen);

        static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);

        static int rtnl_listen(struct rtnl_handle *, int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
                               void *jarg);
        static int rtnl_ask(rtnl_handle *rtnl, struct iovec *iov, size_t iovlen,
                                        struct rtnl_dialog *d, char *buf, int len);
        static struct nlmsghdr* rtnl_wait(rtnl_handle *rth, struct rtnl_dialog *d, int *err);
        static void rtnl_flush(rtnl_handle *rth);
        static int rtnl_tell_iov(rtnl_handle *rth, struct iovec *iov, size_t iovlen);
        static int rtnl_tell(rtnl_handle *rth, struct nlmsghdr *n);
        //static int rtnl_from_file(FILE *, int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
        //                       void *jarg);

};

#endif /* __RTNetlink_H__ */
