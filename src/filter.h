#ifndef FILTER_H
#define FILTER_H

#include <asm/types.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>

#include <string>
#include <vector>

#include "main.h"
#include "sys.h"

class TcFilter {
    public:
        TcFilter(std::string, std::string, std::string, unsigned int, EnumFlowDirection);
        ~TcFilter();
        int store(std::string);
        int validateParams();
        int prepareTcFilter();
        int recoverQos();
        int add(bool);
        int addWAMissLastU32();
        int del();
        __u32 tcFilterId() { return TcFilterId; }
        EnumTcFilterType tcFilterType() { return TcFilterType; }
        unsigned int checkTrafficFromIpt(std::vector  <std::string> &);
        bool getIptRequired();
        bool getIptRequiredToOperate();
        bool getIptRequiredToCheckActivity();
        bool getIptRequiredToCheckTraffic();
   private:
        int parseIpAddr(struct tc_u32_sel *, int, const char *, std::string);
        int getU32(__u32 *val, const char *arg, int base);
        int parseU16(struct tc_u32_sel *sel, int off, int offmask, const char *, const char *);
        int parseU8(struct tc_u32_sel *sel, int off, int offmask, const char *, const char *);
        int packKey(struct tc_u32_sel *, __u32, __u32, int, int);
        int packKey16(struct tc_u32_sel *sel, __u32 key, __u32 mask, int off, int offmask);
        int packKey8(struct tc_u32_sel *sel, __u32 key, __u32 mask, int off, int offmask);
        int getAddr1(inet_prefix *addr, const char *name);
        int getAddrIpv4(__u8 *ap, const char *cp);
        //
        struct tcu32sel TcU32Selector;
        std::string SectionName;
        std::string ClassHeader;
        std::string Dev;
        std::string Match;
        std::string IptMatch;
        EnumNsClassType NsClassType;
        EnumTcFilterType TcFilterType;
        EnumFlowDirection FlowDirection;
        unsigned int DevId;
        unsigned int WaitingRoomId;
        unsigned int FilterId;
        unsigned int HandleFWMark;
        unsigned int FlowId;
        unsigned int Chains;
        bool ImqAutoRedirect;
        bool DestMark;
        //bool FromLocal;
        //bool ToLocal;
        bool UseTcFilter;
        bool IptVirtualAlter;
        __u32 TcFilterId;
};

#endif
