#ifndef WORKER_H
#define WORKER_H

#include "main.h"
#include "niceshaper.h"

class Worker {
    public:
        Worker(std::string, unsigned int, unsigned int, bool);
        ~Worker();	
        //
        int init(std::vector <std::string> &, std::vector <std::string> &);
        int recoverQos();
        int proceedRoundReportValues(struct timeval &, struct timeval &);
        int receiptIptTraffic (std::vector <__u64> &, std::vector <__u64> &);
        int reload(struct timeval, double);
        int statusFormattedAppend(EnumUnits, std::vector <std::string> &);
        void statusTableUnformattedLockUnlockWithTrylock();
        //
        EnumFlowDirection getFlowDirection();
        void setIptRequired(bool);
        void setIptRequiredToCheckActivity(bool);
        bool getIptRequired();
        bool getIptRequiredToCheck();
        void getIptRequirementsIfRequired(bool &, bool &, bool &, bool &);
        std::string getSectionName() { return SectionName; }
        unsigned int getSectionReload();
        void resetReloadsCounter() { ReloadsCounter=0;}
        void incReloadsCounter() { ReloadsCounter++; }
        unsigned int getReloadsCounter() { return ReloadsCounter; }
        //
        struct timeval TVRoundCurr, TVRoundPrev;
        struct timeval TVSleepCurr, TVSleepPrev;
   private:
        std::string statusUndent(std::string, unsigned int);
        std::string statusIndent(std::string, unsigned int);
        int quotaCountersSave();
        int quotaCountersLoad();
        //
        std::string SectionName;
        unsigned int SectionId;
        unsigned int WaitingRoomId;
        unsigned int ReloadsCounter;
        std::vector <std::string> StatusTableUnformatted;
        pthread_mutex_t StatusTableUnformattedLock;
        bool SAOContainter;
        std::string QuotaFile;
        unsigned int QuotaSavePrevSec;
        unsigned int CycleReportPrevSec;
        unsigned int CycleReportMinMsec;
        unsigned int CycleReportMaxMsec;
        unsigned int CycleReportSumMsec;
        unsigned int CycleReportCounter;
        bool CycleReportInitialized;
        class NiceShaper *NS;
};

class WorkerReloadDemand {
    public:
        WorkerReloadDemand(unsigned int, struct timeval);
        ~WorkerReloadDemand();
        //
        unsigned int WorkerVID;
        struct timeval TVReloadDemand;
   private:
};

#endif

