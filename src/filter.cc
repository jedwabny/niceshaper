/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "filter.h"

#include <cstring>
#include <arpa/inet.h>
#include <stdlib.h>
#include <limits.h>

#include <string>
#include <vector>
#include <iostream>

#include "main.h"
#include "aux.h"
#include "config.h"
#include "logger.h"
#include "sys.h"
#include "ifaces.h"
#include "tests.h"

TcFilter::TcFilter(std::string section_name, std::string class_header, std::string match, unsigned int waitingroom_id, EnumFlowDirection flow_direction)
{
    SectionName = section_name;
    FilterId = aux::str_to_uint(aux::value_of_param(match, "_filterid_")); 
    sys->computeQosFilterId(FilterId, &TcFilterId);
    HandleFWMark = 0;
    FlowId = 0;
    Chains = 0;
    DestMark = false;
    UseTcFilter = true;
    IptVirtualAlter = false;
    Dev = "";
    DevId = 0; 
    NsClassType = STANDARD_CLASS;
    TcFilterType = U32;
    FlowDirection = flow_direction;
    ClassHeader = class_header;
    Match = "";    
    WaitingRoomId = waitingroom_id;

    for (unsigned int n=2; n<=aux::awk_size(match); n++) {
        if (n >= 3) Match += " ";

        if (aux::awk(match, n) == "_auto-srcip-dstip_") { 
            if (FlowDirection == DWLOAD) Match += "dstip";
            else if (FlowDirection == UPLOAD) Match += "srcip";
        }
        else {
            Match += aux::awk(match, n);
        }      
    }

    if (aux::value_of_param(match, "_set-mark_").size()) HandleFWMark = aux::str_fwmark_to_uint(aux::value_of_param(match, "_set-mark_"));

    memset(&TcU32Selector, 0, sizeof(TcU32Selector));
}
TcFilter::~TcFilter()
{
    //
}

int TcFilter::store(std::string buf)
{
    std::string option, value1, value2;

    option = aux::awk(buf, 1);
    value1 = aux::awk(buf, 2);
    value2 = aux::awk(buf, 3);

    if (option == "_classid_") {
        FlowId = aux::str_to_uint(value1);
    }

    return 0;
}

int TcFilter::validateParams()
{
    std::string option, value1, value2;
    
    option = aux::awk(ClassHeader, 1);
    value1 = aux::awk(ClassHeader, 2);
    value2 = aux::awk(ClassHeader, 3);

    if (option == "class") {
        NsClassType = STANDARD_CLASS;
        Dev = aux::trim_dev(value2);
        UseTcFilter = true;
    }
    else if (option == "class-virtual") { 
        NsClassType = VIRTUAL;
        Dev = aux::trim_dev(value2);
        IptVirtualAlter = true;
        UseTcFilter = false;
    } 
    else if (option == "class-wrapper") {
        NsClassType = WRAPPER;
        Dev = aux::trim_dev(value1);
        UseTcFilter = true;
    }
    else if (option == "class-do-not-shape") { 
        NsClassType = DONOTSHAPE;
        Dev = aux::trim_dev(value1);
        if (ifaces->isDNShapeMethodSafe(Dev)) FlowId = ifaces->htbDNWrapperId();
        else FlowId = 0;
        UseTcFilter = true;
    } 

    DevId = ifaces->index(Dev);
    TcFilterType = ifaces->tcFilterType(Dev);

    return 0;
}

bool TcFilter::getIptRequired()
{
    if (getIptRequiredToOperate() || getIptRequiredToCheckActivity() || getIptRequiredToCheckTraffic()) return true;   

    return false;
}

bool TcFilter::getIptRequiredToOperate()
{
    if (TcFilterType == FW) return true;
    else if (test->ifaceIsImq(Dev) && config->getImqAutoRedirect()) return true;

    return false;
}

bool TcFilter::getIptRequiredToCheckActivity()
{
    if (TcFilterType == FW) return true;
    else if (sys->getMissU32Perf()) return true;

    return false;
}

bool TcFilter::getIptRequiredToCheckTraffic()
{
    if (IptVirtualAlter) return true;
    else if ((NsClassType == DONOTSHAPE) && config->getStatusShowDoNotShape()) return true;

    return false;
}

int TcFilter::prepareTcFilter()
{
    std::string option, value;
    std::string addr, mask;
    unsigned int n=0;

    if (!UseTcFilter) return 0;
    if (TcFilterType != U32)  return 0;

    TcU32Selector.sel.flags |= TC_U32_TERMINAL;
    while ((aux::awk( Match, ++n)).size()) {
        option = aux::awk( Match, n );
        value = aux::awk( Match, ++n );
        if ( option == "proto" ) {
            if ( value == "tcp" ) { 
                // match ip protocol 6 0xff
                if (parseU8(&TcU32Selector.sel, 9, 0, "6", "0xff") == -1) { log->error(66, Match); return -1; }
            }                     
            else if ( value == "udp" ) { 
                // match ip protocol 17 0xff
                if (parseU8(&TcU32Selector.sel, 9, 0, "17", "0xff") == -1) { log->error(66, Match); return -1; }
            } 
            else if ( value == "icmp" ) { 
                // match ip protocol 1 0xff
                if (parseU8(&TcU32Selector.sel, 9, 0, "1", "0xff" ) == -1) { log->error(66, Match); return -1; }
            } 
            else { log->error(67, Match); return -1; }
        }
        else if ((option == "srcip") || (option == "from-local")) {
            // match ip dst " + addr + "/" + mask
            if (aux::split_ip(value, addr, mask) == -1) { log->error(60, Match); return -1; }
            if (parseIpAddr(&TcU32Selector.sel, 12, addr.c_str(), mask) == -1) { log->error(66, Match); return -1; } 
        }
        else if ((option == "dstip") || (option == "to-local")) {
            // match ip dst " + addr + "/" + mask
            if ((option == "to-local") && (!test->ifaceIsImq(Dev))) { log->error(865, Match); return -1; }
            if (aux::split_ip(value, addr, mask) == -1) { log->error(60, Match); return -1; }
            if (parseIpAddr(&TcU32Selector.sel, 16, addr.c_str(), mask) == -1) { log->error(66, Match); return -1; } 
        }
        else if (( option == "srcport" ) || ( option == "sport" )) {
            // match ip sport " + value + " 0xffff
            if (parseU16(&TcU32Selector.sel, 20, 0, value.c_str(), "0xffff") == -1) { log->error(66, Match); return -1; } 
        }
        else if (( option == "dstport" ) || ( option == "dport" )) {
            // match ip dport " + value + " 0xffff
            if (parseU16(&TcU32Selector.sel, 22, 0, value.c_str(), "0xffff") == -1) { log->error(66, Match); return -1; } 
        }
    }

    return 1;
}

int TcFilter::recoverQos()
{
    DevId = ifaces->index(Dev);

    memset(&TcU32Selector, 0, sizeof(TcU32Selector));

    return 0;
}

int TcFilter::add(bool flow_to_target)
{
    unsigned int flowid = FlowId;

    if (!flow_to_target) flowid = WaitingRoomId;

    if (TcFilterType == U32) {
        if (sys->setQosFilter(QOS_ADD, DevId, FilterId, flowid, TcFilterType, &TcU32Selector) == -1) { return -1; }
    }
    else if (TcFilterType == FW) {
        if (sys->setQosFilter(QOS_ADD, DevId, HandleFWMark, flowid, TcFilterType, NULL) == -1) { return -1; }
    }
 
    return 0;
}

int TcFilter::addWAMissLastU32()
{
    unsigned int flowid = WaitingRoomId;

    if (TcFilterType == U32) {
        if (sys->setQosFilter(QOS_ADD, DevId, 0xFFF, flowid, TcFilterType, &TcU32Selector) == -1) return -1;
        return 0;
    }

    return -1;
}

int TcFilter::del()
{
    if (TcFilterType == U32) {
        if (sys->setQosFilter(QOS_DEL, DevId, FilterId, 0, TcFilterType, NULL) == -1) { return -1; }
    }
    else if (TcFilterType == FW) {
        if (sys->setQosFilter(QOS_DEL, DevId, HandleFWMark, 0, TcFilterType, NULL) == -1) { return -1; }
    }
    
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

int TcFilter::parseIpAddr(struct tc_u32_sel *sel, int off, const char *param1, std::string param2)
{
    inet_prefix addr;
    __u32 mask;
    int offmask = 0;
    int mask_len = 32;

    if (!test->solidIpMask(param2)) {
        log->error( 37, Match );
        return -1;
    }

    if(getAddr1(&addr, param1) == -1) return -1;
    addr.bitlen = mask_len;

    addr.flags |= PREFIXLEN_SPECIFIED;
    if ((addr.bitlen = aux::dot_to_bit(param2)) > mask_len) return -1;

    mask = 0;
    if (addr.bitlen) mask = htonl(0xFFFFFFFF<<(32-addr.bitlen));
    if (packKey(sel, addr.data[0], mask, off, offmask) == -1) return -1;

    return 0;
}

int TcFilter::parseU16(struct tc_u32_sel *sel, int off, int offmask, const char *param1, const char *param2)
{
    __u32 key;
    __u32 mask;

    if (getU32(&key, param1, 0)) return -1;

    if (getU32(&mask, param2, 16)) return -1;

    if (packKey16(sel, key, mask, off, offmask) == -1) return -1;

    return 0;
}

int TcFilter::parseU8(struct tc_u32_sel *sel, int off, int offmask, const char *param1, const char *param2)
{
    __u32 key;
    __u32 mask;

    if (getU32(&key, param1, 0)) return -1;

    if (getU32(&mask, param2, 16)) return -1;

    if (key > 0xFF || mask > 0xFF) return -1;

    if (packKey8(sel, key, mask, off, offmask) == -1) return -1;

    return 0;
}

int TcFilter::packKey(struct tc_u32_sel *sel, __u32 key, __u32 mask, int off, int offmask)
{
    int i;
    int hwm = sel->nkeys;

    key &= mask;

    for (i=0; i<hwm; i++) {
        if (sel->keys[i].off == off && sel->keys[i].offmask == offmask) {
            __u32 intersect = mask&sel->keys[i].mask;

            if ((key^sel->keys[i].val) & intersect)
                return -1;
            sel->keys[i].val |= key;
            sel->keys[i].mask |= mask;
            return 0;
        }
    }

    if (hwm >= 128)
        return -1;
    if (off % 4)
        return -1;
    sel->keys[hwm].val = key;
    sel->keys[hwm].mask = mask;
    sel->keys[hwm].off = off;
    sel->keys[hwm].offmask = offmask;
    sel->nkeys++;
    return 0;
}

int TcFilter::packKey16(struct tc_u32_sel *sel, __u32 key, __u32 mask, int off, int offmask)
{
    if (key > 0xFFFF || mask > 0xFFFF)
        return -1;

    if ((off & 3) == 0) {
        key <<= 16;
        mask <<= 16;
    }
    off &= ~3;
    key = htonl(key);
    mask = htonl(mask);

    return packKey(sel, key, mask, off, offmask);
}

int TcFilter::packKey8(struct tc_u32_sel *sel, __u32 key, __u32 mask, int off, int offmask)
{
    if (key > 0xFF || mask > 0xFF)
        return -1;

    if ((off & 3) == 0) {
        key <<= 24;
        mask <<= 24;
    } else if ((off & 3) == 1) {
        key <<= 16;
        mask <<= 16;
    } else if ((off & 3) == 2) {
        key <<= 8;
        mask <<= 8;
    }
    off &= ~3;
    key = htonl(key);
    mask = htonl(mask);

    return packKey(sel, key, mask, off, offmask);
}

int TcFilter::getU32(__u32 *val, const char *arg, int base)
{
        unsigned long res;
        char *ptr;

        if (!arg || !*arg)
                return -1;
        res = strtoul(arg, &ptr, base);
        if (!ptr || ptr == arg || *ptr || res > 0xFFFFFFFFUL)
                return -1;
        *val = res;
        return 0;
}

int TcFilter::getAddr1(inet_prefix *addr, const char *name)
{
    memset(addr, 0, sizeof(*addr));

    addr->family = AF_INET;

    if (getAddrIpv4((__u8 *)addr->data, name) <= 0)
        return -1;

    addr->bytelen = 4;
    addr->bitlen = -1;
    return 0;
}

/* This uses a non-standard parsing (ie not inet_aton, or inet_pton)
 * because of legacy choice to parse 10.8 as 10.8.0.0 not 10.0.0.8
 */
int TcFilter::getAddrIpv4(__u8 *ap, const char *cp)
{
    int i;

    for (i = 0; i < 4; i++) {
        unsigned long n;
        char *endp;

        n = strtoul(cp, &endp, 0);
        if (n > 255)
            return -1;  /* bogus network value */

        if (endp == cp) /* no digits */
            return -1;

        ap[i] = n;

        if (*endp == '\0')
            break;

        if (i == 3 || *endp != '.')
            return -1;  /* extra characters */
        cp = endp + 1;
    }

    return 1;
}

