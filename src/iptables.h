#ifndef IPTABLES_H
#define IPTABLES_H

#include <string>
#include <vector>

#include "main.h"

#include "worker.h"

class Iptables {
    public:
        Iptables();
        ~Iptables();
        //
        int clean();
        int setHook(EnumFlowDirection, std::string);
        int setChain(EnumFlowDirection, std::string);
        int setTarget(std::string);
        void setDebug(bool);
        void setFallback (bool);
        void setRequirementsIfRequired(bool, bool, bool, bool);
        //
        int prepare(std::vector <std::string> &, std::vector <Worker *> &);
        int init();
        int prepareRules(std::vector <std::string> &, std::vector <Worker *> &);
        int genRulesFromNSMatch(std::string, unsigned int, enum EnumNsClassType NsClassType, EnumFlowDirection, std::string);
        int genFilterFromNSMatch(std::string, EnumFlowDirection, std::string, std::string, std::string, std::string &);
        int checkTraffic(EnumFlowDirection, unsigned int, std::vector <__u64> &, std::vector <__u64> &);
    private:
        int execSysCmd(std::string);
        //
        std::string HookDwload, HookUpload;
        std::string ChainDwload, ChainUpload;
        std::string Target;
        bool RequiredForDwload, RequiredForUpload;
        bool RequiredForCheckDwload, RequiredForCheckUpload;
        std::vector <std::string> Rules;
        std::vector <std::string> RulesDestroy;
        std::vector <unsigned int> AssignHelperDwload, AssignHelperUpload;
        struct timeval TVChainDwloadPrev, TVChainUploadPrev;
        std::vector <std::string> ChainRawCountersDwload, ChainRawCountersUpload;
        bool Debug;
        bool Fallback;        
        bool Initialized;
        unsigned int CacheExpireUsec;
        //
        std::vector<std::string> ProperHooks;
        std::vector<std::string> ProperTargets;
};

#endif

