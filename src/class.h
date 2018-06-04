#ifndef TCCLASS_H
#define TCCLASS_H

#include "filter.h"
#include "trigger.h"

class NsClass {
    public:
        NsClass(std::string, unsigned int, unsigned int, EnumFlowDirection, unsigned int);
        ~NsClass();
        void setAsDnswStub();
        int store(std::string);
        int recoverQos();
        bool getIptRequired();
        bool getIptRequiredToOperate();
        bool getIptRequiredToCheckActivity();
        bool getIptRequiredToCheckTraffic();
        int validateParams();
        int prepareQosClass();
        int prepareAndAddQosFilters();
        int proceedQosFilterHits(__u32, __u64);
        int proceedReceiptTraffic(__u64 raw_bytes);
        int proceedReceiptIptCountersSum(__u64);
        int proceedReceiptedTraffic(struct timeval, double);
        unsigned int trafficPrognosed();
        void computeGrade();
        int add();
        int addWAMissLastU32();
        int del();
        int applyChanges(unsigned int workings_count);
        int proceedTriggers (struct timeval);
        std::string status();
        std::string dumpQuotaCounters();
        void setQuotaCounters (unsigned int, unsigned int, unsigned int);
        //
        unsigned int getHold() { return Hold; } 
        bool getUseQosClass() { return UseQosClass; }
        bool getUseQosFilter() { return UseQosFilter; }
        bool getActive() { return Active; }
        bool getQosInitialized() { return QosInitialized; }
        EnumNsClassType type() { return NsClassType; }
        __u32 qosClassId() { return QosClassId; }
        unsigned int traffic() { return Traffic; }        
        unsigned int htbCeil() { return HtbCeil; }
        unsigned int htbBurst() { return HtbBurst; }
        unsigned int htbCBurst() { return HtbCBurst; }
        unsigned int nsLow() { return NsLow; }
        unsigned int nsCeil() { return NsCeil; }
        double gradeForReducing() { return GradeForReducing; }
        std::string name() { return Name; }
        void decHtbCeil( unsigned int decrease ) { HtbCeil -= decrease; }
        void incHtbCeil( unsigned int increase ) { HtbCeil += increase; }
        void setHtbCeil( unsigned int htb_ceil ) { HtbCeil = htb_ceil; }
        void setTraffic( unsigned int traffic ) { Traffic = traffic; }
        unsigned int getTcFiltersNum();
        unsigned int getDnswStubBefore() { return DnswStubBefore; }
        std::string getDev() { return Dev; }
        __u32 getTcFilterU32MaxId();
    private:
        std::string SectionName;
        std::string Header;
        std::string Dev;
        std::string Name;
        std::string EsfqHash;
        std::string TcQdiscEsfqAdd;
        EnumNsClassType NsClassType;
        EnumTcQdiscType TcQdiscType;
        EnumFlowDirection FlowDirection;
        TriggerAlter Alter;
        TriggerQuota Quota;
        unsigned int DevId;
        unsigned int ClassId;
        __u32 QosClassId;
        unsigned int Alive;
        unsigned int Hold;
        unsigned int NsLow;
        unsigned int NsCeil;
        unsigned int HtbParentId;
        unsigned int WaitingRoomId;
        unsigned int HtbRate;
        unsigned int HtbCeil;
        unsigned int HtbPrio;
        unsigned int HtbBurst;
        unsigned int HtbCBurst;
        unsigned int OldHtbRate;
        unsigned int OldHtbCeil;
        unsigned int SfqPerturb;
        unsigned int EsfqPerturb;
        unsigned int SectionShape;
        unsigned int Traffic;
        __u64 RawBytesCurr;
        __u64 RawBytesPrev;
        __u64 RawBytesIptPrev;
        double GradeForReducing; // 0 to 1
        double Strict;
        bool UseQosClass;
        bool UseQosFilter;
        bool StatusShowHtbCeil;
        bool StatusShowTraffic;
        bool Active;      
        bool QosInitialized;
        std::vector <TcFilter *> TcFilters;
        // Dnsw stub related
        bool DnswStub;
        unsigned int DnswStubBefore;
        unsigned int DnswStubTcFiltersNum;
};

#endif
