#ifndef NICESHAPER_H
#define NICESHAPER_H

#include <sys/time.h>

#include "class.h"

class NiceShaper {
    public:
        NiceShaper(std::string, unsigned int, unsigned int, bool);
        ~NiceShaper();
        int init(std::vector <std::string> &, std::vector <std::string> &);
        int initQos();
        int recoverQos();
        EnumFlowDirection getFlowDirection();
        void setIptRequired(bool);
        void setIptRequiredToCheckActivity(bool);
        bool getIptRequired();
        bool getIptRequiredToCheck();
        int receiptIptTraffic (std::vector <__u64> &, std::vector <__u64> &);
        int judge(struct timeval, double);
        int statusUnformatted(std::vector <std::string> &);
        std::vector <std::string> dumpQuotaCounters ();
        int setQuotaCounters (std::vector <std::string> &);
        unsigned int getReload() { return Reload; };
    private:
        int qosCheckClassesBytes();
        int qosCheckFiltersHits();
        int judgeV12();
        int applyChanges();  
        //
        std::string SectionName; 
        unsigned int SectionId;
        unsigned int WaitingRoomId;
        unsigned int SectionHtbCeil;
        unsigned int SectionShape;
        unsigned int Reload;
        EnumFlowDirection FlowDirection;
        std::vector <std::string> SectionIfaces;
        bool SAOContainter;
        bool IptRequired;
        bool IptRequiredToCheckActivity;
        bool IptRequiredToCheckTraffic;
        bool DnswDoNotShape;
        bool DnswWrapper;
        unsigned int SectionTraffic;
        unsigned int SectionHtbBurst;
        unsigned int SectionHtbCBurst;
        unsigned int Working;
        double CrossBar;     
        std::vector <NsClass *> NsClasses;
        std::vector <NsClass *> NsClassesDnswStubs;
        std::vector <__u64> IptOrderedCounters;
        std::vector <__u64> IptOrderedCountersDnsw;
};

#endif


