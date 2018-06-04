#ifndef SYS_H
#define SYS_H

#define TIME_UNITS_PER_SEC  1000000
#define PREFIXLEN_SPECIFIED 1

#include <string>
#include <vector>

#include "libnetlink.h"

#include "main.h"

typedef struct rfy
{
    __u8 family;
    __u8 bytelen;
    __s16 bitlen;
    __u32 flags;
    __u32 data[8];
} inet_prefix;

struct tcu32sel
{
    struct tc_u32_sel sel;
    struct tc_u32_key keys[128];
};

class QosClassBytes
{
    public:
        QosClassBytes(__u32, __u64);
        ~QosClassBytes();
    __u32 QosClassId;
    __u64 Bytes;
};

class QosFilterHits
{
    public:
        QosFilterHits(__u32, __u64);
        ~QosFilterHits();
    __u32 QosFilterId;
    __u64 Hits;
};

class Sys 
{
    public:
        Sys();
        ~Sys();
        int qosCoreInit();
        int rtnlOpen();
        void rtnlClose();
        int setQosClass(EnumTcOperation, int, unsigned int, unsigned int, 
                    unsigned, unsigned, unsigned, unsigned, unsigned int, unsigned int); // cmd, ifindex, parent_id, class_id, rate, ceil, prio, quantum, burst, cburst
        int setQosQdisc(EnumTcOperation, int, unsigned int, unsigned int, EnumTcQdiscType, int); // cmd, ifindex, parent_id, handle_id, qdisc_type, htb->default|sfq->perturb
        int setQosFilter(EnumTcOperation, int, unsigned int, unsigned int, EnumTcFilterType, struct tcu32sel *); // cmd, ifindex, handle_id, flow_id, tc_filter_kind
        int cleanAccountingHelpers();
        int qosCheck(int, EnumTcObjectType);
        int qosCheckClassesBytes(const struct sockaddr_nl *who, struct nlmsghdr *n);
        int qosCheckFiltersHits(const struct sockaddr_nl *who, struct nlmsghdr *n);
        int computeQosClassId(unsigned int, unsigned int, __u32 *h);
        int computeQosQdiscHandle(unsigned int, __u32 *h);
        int computeQosFilterId(unsigned int, __u32 *);
        void setMissU32Perf(bool miss_u32_perf) { MissU32Perf = miss_u32_perf; }
        bool getMissU32Perf() { return MissU32Perf; }
        std::vector <class QosClassBytes *> QosClassesBytes;
        std::vector <class QosFilterHits *> QosFiltersHits;
    private:
        int getHz();
        int qosCalcRtable(int cell_log, unsigned mtu, struct tc_ratespec *r, __u32 *rtab);
        int qosCalcSizeTable(struct tc_sizespec *s, __u16 **stab);
        unsigned qosCalcXmittime(unsigned rate, unsigned size);
        unsigned qosCoreTime2tick(unsigned time);
        unsigned qosAdjustSize(unsigned, unsigned);
        double TickInUsec;
        double ClockFactor;
        bool MissU32Perf;
        RTNetlink::rtnl_handle *NetlinkHandle;
};

#endif
