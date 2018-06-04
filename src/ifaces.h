#ifndef IFACESMAP_H
#define IFACESMAP_H

#include <string>
#include <vector>

#include "main.h"

class Iface
{
    friend class IfacesMap;
    public:
        Iface(int ifr_ifindex, std::string ifr_name);
        ~Iface();
    private:
        int Index;
        std::string Name;
        bool Controlled;
        bool QosInitialized;
        bool DNShapeMethodSafe;
        bool HtbDNWrapperClass;
        unsigned int Speed;
        unsigned int FallbackRate;
        std::vector <std::string> Sections;
        unsigned int SectionsSpeedSum;
        unsigned int HtbFallbackId; 
        EnumTcFilterType TcFilterType;
        EnumFlowDirection FlowDirection; 
        __u32 TcFilterU32MinId;
        __u32 TcFilterU32MaxId;
        bool WAMissLastU32Used;
};

class IfacesMap
{
    public:
        IfacesMap();
        ~IfacesMap();
        int discover();
        int index(std::string);
        bool isValidSysDev(std::string);
        void setAsControlled(std::string);
        void setDNShapeMethodSafe(std::string, bool);
        bool isDNShapeMethodSafe(std::string);
        void setHtbDNWrapperClass(std::string, bool);
        void setUnclassifiedMethodFallbackClass(std::string, bool);
        void setSpeed(std::string, unsigned int);
        unsigned int speed(std::string);
        void setFallbackRate(std::string, unsigned int);
        void addSection(std::string, std::string);
        bool isInSections(std::string, std::string); 
        int addToSectionsSpeedSum(std::string, unsigned int);
        void setTcFilterType(std::string, EnumTcFilterType);
        EnumTcFilterType tcFilterType(std::string);
        int initHtbOnControlled();
        int endUpHtbFallbackOnControlled();
        unsigned int htbDNWrapperId();
        int setFlowDirection(std::string, EnumFlowDirection);
        EnumFlowDirection getFlowDirection(std::string);
        void reportTcFilterU32Id(std::string, __u32);
        __u32 getTcFilterU32MinId(std::string);
        __u32 getTcFilterU32MaxId(std::string);
        void setWAMissLastU32Used(std::string, bool);
        bool getWAMissLastU32Used(std::string);
    private:
        int ifaceNum(std::string);
        unsigned int HtbDNWrapperId;  
        std::vector <Iface *> SysNetDevices;
};

#endif

