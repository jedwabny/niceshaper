/*
 *  NiceShaper - Dynamic Traffic Management
 *
 *  Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 */

#include "sys.h"

#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <linux/gen_stats.h>

#include <string>

#include "libnetlink.h"

#include "main.h"
#include "aux.h"
#include "logger.h"
#include "ifaces.h"

QosClassBytes::QosClassBytes(__u32 qos_class_id, __u64 bytes)
{
    QosClassId = qos_class_id;
    Bytes = bytes;
}

QosClassBytes::~QosClassBytes()
{
    // nothing
}

QosFilterHits::QosFilterHits(__u32 qos_filter_id, __u64 hits)
{
    QosFilterId = qos_filter_id;
    Hits = hits;
}

QosFilterHits::~QosFilterHits()
{
    // nothing
}

Sys::Sys ()
{
    NetlinkHandle = new RTNetlink::rtnl_handle;
    TickInUsec = 1;
    ClockFactor = 1;
    MissU32Perf = false;
    qosCoreInit();
}

Sys::~Sys ()
{
    // nothing
}

int Sys::rtnlOpen()
{
    if (RTNetlink::rtnl_open(NetlinkHandle, 0) == -1) {
        log->setReqRecoverQos(true);
        return -1;
    }

    return 0;
}

void Sys::rtnlClose()
{
    RTNetlink::rtnl_close(NetlinkHandle);
}

/* 
 * This part of code is based on the iproute2 code by:
 *
 * Authors: Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

int Sys::setQosClass(EnumTcOperation operation, int iface_index, unsigned int tc_parent_id, unsigned int tc_class_id, 
                unsigned int tc_class_rate, unsigned int tc_class_ceil,
                unsigned int tc_class_prio, unsigned int tc_class_quantum,
                unsigned int buffer, unsigned int cbuffer)
{
    struct {
        struct nlmsghdr     n;
        struct tcmsg        t;
        char            buf[4096];
    } req;
    char  k[16];
    struct tc_htb_opt htb_opt;
    __u32 rtab[256], ctab[256];
    int cell_log=-1, ccell_log = -1;
    unsigned mtu = 1600; /* eth packet len */
    unsigned short mpu = 0;
    struct rtattr *tail;

    memset(&req, 0, sizeof(req));
    memset(k, 0, sizeof(k));
    memset(&htb_opt, 0, sizeof(htb_opt)); 
    
    // Set flags
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    if (operation == QOS_ADD) {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
        req.n.nlmsg_type = RTM_NEWTCLASS;
    } 
    else if (operation == QOS_MOD) {
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = RTM_NEWTCLASS;
    }
    else if (operation == QOS_REP) {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE;
        req.n.nlmsg_type = RTM_NEWTCLASS;
    }
    else if (operation == QOS_DEL) {
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = RTM_DELTCLASS;
    } 
    else {
        return -1;
    }
    req.t.tcm_ifindex = iface_index;
    req.t.tcm_family = AF_UNSPEC;

    if (computeQosClassId(1, tc_class_id, &req.t.tcm_handle) == -1) return -1;
    if (computeQosClassId(1, tc_parent_id, &req.t.tcm_parent) == -1) return -1;

    strncpy(k, "htb", sizeof(k)-1);

    if (k[0])
        RTNetlink::addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);

    htb_opt.prio = tc_class_prio;
    htb_opt.quantum = tc_class_quantum;

    htb_opt.rate.rate = tc_class_rate/8;
    htb_opt.ceil.rate = tc_class_ceil/8;

    /* compute minimal allowed burst from rate; mtu is added here to make
       sure that buffer is larger than mtu and to have some safeguard space */
    if (!buffer) buffer = htb_opt.rate.rate / getHz() + mtu;
    if (!cbuffer) cbuffer = htb_opt.ceil.rate / getHz() + mtu;
    htb_opt.ceil.overhead = 0;
    htb_opt.rate.overhead = 0;

    htb_opt.ceil.mpu = mpu;
    htb_opt.rate.mpu = mpu;

    if (qosCalcRtable(cell_log, mtu, &htb_opt.rate, rtab) < 0) {
        log->error(53, "htb: failed to calculate rate table");
        return -1;
    }
    htb_opt.buffer = qosCalcXmittime(htb_opt.rate.rate, buffer);

    if (qosCalcRtable(ccell_log, mtu, &htb_opt.ceil, ctab) < 0) {
        log->error(53, "htb: failed to calculate ceil rate table");
        return -1;
    }
    htb_opt.cbuffer = qosCalcXmittime(htb_opt.ceil.rate, cbuffer);

    tail = (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len));
    RTNetlink::addattr_l(&req.n, 1024, TCA_OPTIONS, NULL, 0);
    RTNetlink::addattr_l(&req.n, 2024, TCA_HTB_PARMS, &htb_opt, sizeof(htb_opt));
    RTNetlink::addattr_l(&req.n, 3024, TCA_HTB_RTAB, rtab, 1024);
    RTNetlink::addattr_l(&req.n, 4024, TCA_HTB_CTAB, ctab, 1024);
    tail->rta_len = (char *) (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len)) - (char *) tail;
    //if (
    //  RTNetlink::rtnl_talk(NetlinkHandle, &req.n, 0, 0, NULL, NULL, NULL);
    //return 2;

    if (RTNetlink::rtnl_tell(NetlinkHandle, &req.n) < 0) return -1;

    return 0;
}

int Sys::setQosQdisc (EnumTcOperation operation, int iface_index, unsigned int tc_parent_id, unsigned int tc_handle_id, EnumTcQdiscType tc_qdisc_kind, int qdisc_param1)
{
    char  k[16];
    struct {
        struct nlmsghdr     n;
        struct tcmsg        t;
        //char            buf[TCA_BUF_MAX];
        char            buf[(64*1024)];
    } req;
    struct tc_sfq_qopt sfq_opt;
    struct tc_htb_glob htb_opt;
    struct rtattr *tail;
    memset(&req, 0, sizeof(req));
    memset(&k, 0, sizeof(k));
    memset(&sfq_opt,0,sizeof(sfq_opt));
    memset(&htb_opt,0,sizeof(htb_opt));

    // Set flags
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    if (operation == QOS_ADD) {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
        req.n.nlmsg_type = RTM_NEWQDISC;
    }
    else if (operation == QOS_REP) {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE;
        req.n.nlmsg_type = RTM_NEWQDISC;
    }
    else if (operation == QOS_DEL) {
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = RTM_DELQDISC;
    }
    else {
        return -1;
    }

    req.t.tcm_ifindex = iface_index;
    req.t.tcm_family = AF_UNSPEC;

    if (computeQosClassId(1, tc_parent_id, &req.t.tcm_parent) == -1) return -1;
    if (operation == QOS_DEL) {
        RTNetlink::rtnl_tell(NetlinkHandle, &req.n);
        return 0;
    }
    if (computeQosQdiscHandle(tc_handle_id, &req.t.tcm_handle) == -1) return -1;

    if (tc_qdisc_kind == SFQ) strncpy(k, "sfq", sizeof(k)-1);
    else if (tc_qdisc_kind == HTB) strncpy(k, "htb", sizeof(k)-1);
    else return -1;

    if (k[0])
        RTNetlink::addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);

    if (tc_qdisc_kind == SFQ) {    
        sfq_opt.perturb_period = qdisc_param1;
        RTNetlink::addattr_l(&req.n, 1024, TCA_OPTIONS, &sfq_opt, sizeof(sfq_opt));
    } 
    else if (tc_qdisc_kind == HTB) {
        tail = (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len));
        htb_opt.version = 3;
        htb_opt.rate2quantum = 10;
        htb_opt.defcls = qdisc_param1;
        tail = (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len));
        RTNetlink::addattr_l(&req.n, 1024, TCA_OPTIONS, NULL, 0);
        RTNetlink::addattr_l(&req.n, 2024, TCA_HTB_INIT, &htb_opt, NLMSG_ALIGN(sizeof(htb_opt)));
        tail->rta_len = (char *) (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len)) - (char *) tail;
    }

    if (RTNetlink::rtnl_tell(NetlinkHandle, &req.n) < 0) return -1;

    return 0;
}

int Sys::setQosFilter(EnumTcOperation operation, int iface_index, unsigned int tc_handle_id, unsigned int tc_flowid_id, EnumTcFilterType tc_filter_kind, struct tcu32sel *tc_u32_selector)
{
    struct {
        struct nlmsghdr     n;
        struct tcmsg        t;
        char            buf[16384];
    } req;
    __u32 prio = 10;
    __u32 protocol = 0;
    char  k[16];
    struct rtattr *tail;

    memset(&req, 0, sizeof(req));
    memset(k, 0, sizeof(k));

    // Set flags
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
    if (operation == QOS_ADD) {
        req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_CREATE;
        req.n.nlmsg_type = RTM_NEWTFILTER;
        if (req.n.nlmsg_flags & NLM_F_CREATE) protocol = ETH_P_ALL;
   }
    else if (operation == QOS_DEL) {
        req.n.nlmsg_flags = NLM_F_REQUEST;
        req.n.nlmsg_type = RTM_DELTFILTER;
    }
    else {
        return -1;
    }

    req.t.tcm_ifindex = iface_index;
    req.t.tcm_family = AF_UNSPEC;

    protocol = htons(0x0800);

    if (tc_filter_kind == U32) {
        strncpy(k, "u32", sizeof(k)-1);
        if (computeQosFilterId(tc_handle_id, &req.t.tcm_handle) == -1) return -1;
    }
    else if (tc_filter_kind == FW) {
        strncpy(k, "fw", sizeof(k)-1);
        req.t.tcm_handle = tc_handle_id;
    }
    else return -1;

    req.t.tcm_info = TC_H_MAKE(prio<<16, protocol);

    RTNetlink::addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);

    if (operation == QOS_ADD) {
        unsigned hhandle;
        tail = (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len));
        RTNetlink::addattr_l(&req.n, 16384, TCA_OPTIONS, NULL, 0);
        if (computeQosClassId(1, tc_flowid_id, &hhandle) == -1) {
            log->error(53, "htb: Illegal _classid_");
            return -1;
        }

        if (tc_filter_kind == U32) {
            RTNetlink::addattr_l(&req.n, 16384, TCA_U32_CLASSID, &hhandle, 4);
            RTNetlink::addattr_l(&req.n, 16384, TCA_U32_SEL, tc_u32_selector, sizeof((*tc_u32_selector).sel)+(*tc_u32_selector).sel.nkeys*sizeof(struct tc_u32_key));
        }
        else if (tc_filter_kind == FW) {
            RTNetlink::addattr_l(&req.n, 4096, TCA_FW_CLASSID, &hhandle, 4);
        }
        else return -1;
        
        tail->rta_len = (char *) (struct rtattr*)(((char*)&req.n) + NLMSG_ALIGN(req.n.nlmsg_len)) - (char *) tail;
    }   

    if (RTNetlink::rtnl_tell(NetlinkHandle, &req.n) < 0) {
        return -1;
    }

    return 0; 
}

int Sys::cleanAccountingHelpers()
{
    for (unsigned int n=0; n<QosClassesBytes.size(); n++) { delete QosClassesBytes.at(n); }
    for (unsigned int n=0; n<QosFiltersHits.size(); n++) { delete QosFiltersHits.at(n); }

    QosClassesBytes.clear();
    QosFiltersHits.clear();

    return 0;
}

int Sys::qosCheck(int iface_index, EnumTcObjectType tc_scope_object)
{
    struct tcmsg t;
    char d[16];
    __u32 prio = 0;
    __u32 protocol = 0;
    int rtm_type = RTM_GETTCLASS;
    
    memset(&t, 0, sizeof(t));
    memset(d, 0, sizeof(d));

    t.tcm_ifindex = iface_index;
    t.tcm_family = AF_UNSPEC;

    if (tc_scope_object == QOS_CLASS) {
        rtm_type = RTM_GETTCLASS;
    }
    else if (tc_scope_object == QOS_FILTER) {
        rtm_type = RTM_GETTFILTER;
        t.tcm_info = TC_H_MAKE(prio<<16, protocol);
    }
    else {
        log->error(999, "int Sys::qosCheck");
        return -1;
    }

    if (RTNetlink::rtnl_dump_request(NetlinkHandle, rtm_type, &t, sizeof(t)) < 0) {
        log->error(52, "Cannot send dump request");
        return -1;
    }

    if (RTNetlink::rtnl_dump_filter(NetlinkHandle, NULL, NULL, NULL, NULL, tc_scope_object) < 0) {
       log->error(52, "Dump terminated");
       return -1;
    }

    return 0;
}

int Sys::qosCheckClassesBytes(const struct sockaddr_nl *who, struct nlmsghdr *n)
{
    struct tcmsg *t = ((struct tcmsg *)(((char*)n) + NLMSG_LENGTH(0)));
    struct rtattr *tb[TCA_MAX+1];
    struct rtattr *tbs[TCA_STATS_MAX + 1];
    struct gnet_stats_basic bs = {0};
    class QosClassBytes *s;
    int len = n->nlmsg_len;

    if (n->nlmsg_type != RTM_NEWTCLASS) {
        log->error(52, "Not a class or deleted");
        return 0;
    }

    len -= NLMSG_LENGTH(sizeof(*t));
    if (len < 0) {
        log->error(52, "Wrong len " + aux::int_to_str(len));
        return -1;
    }

    memset(tb, 0, sizeof(tb));
    memset(tbs, 0, sizeof(tbs));

    RTNetlink::parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);

    if (tb[TCA_KIND] == NULL) {
        log->error(52, "print_class: NULL kind");
        return -1;
    }

    if (!t->tcm_handle) return 0;
    if (!tb[TCA_STATS2]) return 0;

    RTNetlink::parse_rtattr(tbs, TCA_STATS_MAX, ((struct rtattr*)(((char*)(tb[TCA_STATS2])) + RTA_LENGTH(0))), RTA_PAYLOAD(tb[TCA_STATS2]));

    if (!tbs[TCA_STATS_BASIC]) return 0;

    memcpy(&bs, RTA_DATA(tbs[TCA_STATS_BASIC]), MIN(RTA_PAYLOAD(tbs[TCA_STATS_BASIC]), sizeof(bs)));
    s = new QosClassBytes(t->tcm_handle, bs.bytes);
    QosClassesBytes.push_back(s);

    return 0;
}

int Sys::qosCheckFiltersHits(const struct sockaddr_nl *who, struct nlmsghdr *n)
{
    struct tcmsg *t = ((struct tcmsg *)(((char*)n) + NLMSG_LENGTH(0)));
    int len = n->nlmsg_len;
    struct rtattr *tb[TCA_MAX+1];
    struct rtattr *tba[TCA_U32_MAX+1];
    struct tc_u32_pcnt *pf = NULL;
    class QosFilterHits *s;

    if (n->nlmsg_type != RTM_NEWTFILTER) {
        log->error(52, "Not a filter or deleted");
        return 0;
    }

    len -= NLMSG_LENGTH(sizeof(*t));
    if (len < 0) {
        log->error(52, "Wrong len " + aux::int_to_str(len));
        return -1;
    }

    memset(tb, 0, sizeof(tb));
    memset(tba, 0, sizeof(tba));

    RTNetlink::parse_rtattr(tb, TCA_MAX, TCA_RTA(t), len);

    if (!tb[TCA_OPTIONS]) return 0;

    if (tb[TCA_KIND] == NULL) {
        log->error(52, "print_filter: NULL kind");
        return -1;
    }

    RTNetlink::parse_rtattr(tba, TCA_U32_MAX, ((struct rtattr*)(((char*)(tb[TCA_OPTIONS])) + RTA_LENGTH(0))), RTA_PAYLOAD(tb[TCA_OPTIONS]));

    if (!tba[TCA_U32_PCNT]) {
        if (t->tcm_handle == static_cast<__u32>(0x800<<20)) return 0;
        log->error(502);
        log->setReqRecoverMissU32Perf(true);
        setMissU32Perf(true);
        return -1;
    }

    if (RTA_PAYLOAD(tba[TCA_U32_PCNT]) < sizeof(*pf)) {
        log->error(52, "Broken perf counters");
        return -1;
    }

    pf = ((tc_u32_pcnt*)(((char*)(tba[TCA_U32_PCNT])) + RTA_LENGTH(0)));

    if (pf == NULL) return 0;

    s = new QosFilterHits(t->tcm_handle, pf->rhit);
    QosFiltersHits.push_back(s);

    return 0;
}

/*
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 * Authors: Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *          Mariusz Jedwabny, <mariusz@jedwabny.net> - Adapt to NiceShaper
 */

int Sys::qosCoreInit()
{
    FILE *fp;
    __u32 clock_res;
    __u32 t2us;
    __u32 us2t;

    fp = fopen("/proc/net/psched", "r");
    if (fp == NULL)
        return -1;

    if (fscanf(fp, "%08x%08x%08x", &t2us, &us2t, &clock_res) != 3) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* compatibility hack: for old iproute binaries (ignoring
     * the kernel clock resolution) the kernel advertises a
     * tick multiplier of 1000 in case of nano-second resolution,
     * which really is 1. */
    if (clock_res == 1000000000)
        t2us = us2t;

    ClockFactor  = (double)clock_res / TIME_UNITS_PER_SEC;
    TickInUsec = (double)t2us / us2t * ClockFactor;
    return 0;
}

int Sys::computeQosClassId(unsigned int major, unsigned int minor, __u32 *h)
{
    __u32 maj, min;

 //   if ((major == 1) && (minor == 0)) {
     if ((major == 1) && (minor == TC_H_ROOT)) {
        *h = TC_H_ROOT;
        return 0;
    }

    maj = major; // major can be 0
    if (major) {
        maj = major;
    }

    //if (minor == 0) return -1;
    if (maj >= (1<<16)) return -1;
    maj <<= 16;
    min = minor;
    if (min >= (1<<16)) return -1;
    maj |= min;
    *h = maj;

    return 0;
}

int Sys::computeQosQdiscHandle(unsigned int major, __u32 *h)
{
    __u32 maj;

    if (major == 0) return -1;

    maj = major;
    maj <<= 16;
    *h = maj;

    return 0;
}

int Sys::computeQosFilterId(unsigned int minor, __u32 *h)
{
    *h = (2048<<20)|minor;

    return 0;
}

int Sys::getHz()
{
    char name[1024];
    int hz = 0;
    FILE *fp;

    if (getenv("HZ"))
        return atoi(getenv("HZ")) ? atoi(getenv("HZ")) : HZ;

    if (getenv("PROC_NET_PSCHED")) {
        snprintf(name, sizeof(name)-1, "%s", getenv("PROC_NET_PSCHED"));
    } else if (getenv("PROC_ROOT")) {
        snprintf(name, sizeof(name)-1, "%s/net/psched", getenv("PROC_ROOT"));
    } else {
        strcpy(name, "/proc/net/psched");
    }
    fp = fopen(name, "r");

    if (fp) {
        unsigned nom, denom;
        if (fscanf(fp, "%*08x%*08x%08x%08x", &nom, &denom) == 2)
            if (nom == 1000000)
                hz = denom;
        fclose(fp);
    }
    if (hz)
        return hz;

    return HZ;
}

int Sys::qosCalcRtable(int cell_log, unsigned mtu, struct tc_ratespec *r, __u32 *rtab)
{
    int i;
    unsigned sz;
    unsigned bps = r->rate;
    unsigned mpu = r->mpu;

    if (mtu == 0)
        mtu = 2047;

    if (cell_log < 0) {
        cell_log = 0;
        while ((mtu >> cell_log) > 255)
            cell_log++;
    }

    for (i=0; i<256; i++) {
        sz = qosAdjustSize((i + 1) << cell_log, mpu);
        rtab[i] = qosCalcXmittime(bps, sz);
    }

    r->cell_align=-1; // Due to the sz calc
    r->cell_log=cell_log;
    return cell_log;
}

unsigned Sys::qosCalcXmittime(unsigned rate, unsigned size)
{
    return qosCoreTime2tick(TIME_UNITS_PER_SEC*((double)size/rate));
}

unsigned Sys::qosCoreTime2tick(unsigned time)
{
    return time*TickInUsec;
}

unsigned Sys::qosAdjustSize(unsigned sz, unsigned mpu)
{
    if (sz < mpu)
        sz = mpu;

    return sz;
}

 

