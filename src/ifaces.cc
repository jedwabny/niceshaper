/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "ifaces.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <string>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "main.h"
#include "aux.h"
#include "logger.h"
#include "sys.h"
#include "tests.h"

Iface::Iface(int iface_index, std::string iface_name) 
{ 
    Index = iface_index; 
    Name = aux::trim_dev(iface_name); 
    Controlled = false;
    QosInitialized = false;
    DNShapeMethodSafe = true;
    HtbDNWrapperClass = false;
    Speed = 0;
    FallbackRate = 100 * 1000; // 100kb/s
    Sections.clear();
    SectionsSpeedSum = 0;
    HtbFallbackId = 9;
    TcFilterType = U32;
    FlowDirection = UNSPEC;
    sys->computeQosFilterId(0xFFF, &TcFilterU32MinId);
    sys->computeQosFilterId(0x000, &TcFilterU32MaxId);
    WAMissLastU32Used = false;
}

Iface::~Iface()
{
    //
}

IfacesMap::IfacesMap () 
{
    HtbDNWrapperId = 8;

    discover();
}

IfacesMap::~IfacesMap () 
{
    std::string buf;
    Iface *dev;

    // Erase HTB from interfaces
    sys->rtnlOpen();
    for (unsigned int n=0; n < SysNetDevices.size(); n++) 
    { 
        dev = SysNetDevices.at(n);
        if (dev->Controlled && dev->QosInitialized) sys->setQosQdisc(QOS_DEL, dev->Index, TC_H_ROOT, 1, HTB, 0);
    }
    sys->rtnlClose();
}

int IfacesMap::discover()
{
    // Complete system devices
    struct ifreq *ifr;
    struct ifreq ifr2;
    struct ifconf ifc;
    unsigned int query_devs=0;
    int iface_num;
    int sd;

    sd = socket (PF_INET, SOCK_STREAM, 0);

    do {
        if (query_devs) delete [] ifr;
        query_devs++;
        ifr = new ifreq[query_devs];
        ifc.ifc_len = query_devs * sizeof (struct ifreq);
        ifc.ifc_req = ifr;
        ioctl (sd, SIOCGIFCONF, &ifc);
    } while (query_devs == ifc.ifc_len / sizeof(struct ifreq));

    for (unsigned int i = 0; i < (ifc.ifc_len / sizeof (struct ifreq)); i++) {
        strncpy(ifr2.ifr_name, ifr[i].ifr_name, sizeof(ifr2.ifr_name));
        ioctl (sd, SIOCGIFINDEX, &ifr2);
        iface_num = ifaceNum(std::string(ifr[i].ifr_name));
        if (iface_num == -1) {
            SysNetDevices.push_back(new Iface(ifr2.ifr_ifindex, std::string(ifr[i].ifr_name)));
        }
        else {
            SysNetDevices.at(iface_num)->Index = ifr2.ifr_ifindex;
        }
    }

    // Checking for IMQ devices.
    int n = 0;
    do {
	    int ifindex = 0;

        sprintf(ifr2.ifr_name, "imq%d", n);
        if (ioctl(sd, SIOCGIFINDEX, &ifr2) < 0) break;
     	ifindex = ifr2.ifr_ifindex;
        if (ioctl(sd, SIOCGIFFLAGS, &ifr2) < 0) break;
        iface_num = ifaceNum(std::string(ifr2.ifr_name));
        if (iface_num == -1) {
            SysNetDevices.push_back(new Iface(ifindex, std::string(ifr2.ifr_name)));
        }
        else {
            SysNetDevices.at(iface_num)->Index = ifindex;
        }
        n++;
    } while (n);
 
    close(sd);

    return 0;
}

int IfacesMap::ifaceNum(std::string dev)
{
    for (unsigned int n=0; n < SysNetDevices.size(); n++) {
        if (SysNetDevices.at(n)->Name == dev) return n;
    }

    return -1;
}

int IfacesMap::index(std::string dev)
{
    if (ifaceNum(dev) == -1) return -1;

    return SysNetDevices.at(ifaceNum(dev))->Index;
}

bool IfacesMap::isValidSysDev(std::string dev)
{
    if (ifaceNum(dev) == -1) return false;

    return true;
}

void IfacesMap::setAsControlled(std::string dev)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->Controlled = true;
}

void IfacesMap::setDNShapeMethodSafe(std::string dev, bool arg)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->DNShapeMethodSafe = arg;
}

bool IfacesMap::isDNShapeMethodSafe(std::string dev)
{
    if (ifaceNum(dev) == -1) return true;

    return SysNetDevices.at(ifaceNum(dev))->DNShapeMethodSafe;
}

void IfacesMap::setHtbDNWrapperClass(std::string dev, bool arg)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->HtbDNWrapperClass = arg;
}

void IfacesMap::setUnclassifiedMethodFallbackClass(std::string dev, bool arg)
{
    if (ifaceNum(dev) == -1) return;

    if (arg == true) SysNetDevices.at(ifaceNum(dev))->HtbFallbackId = 9;
    else SysNetDevices.at(ifaceNum(dev))->HtbFallbackId = 0;
}

void IfacesMap::setSpeed(std::string dev, unsigned int iface_speed)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->Speed = iface_speed;
}

unsigned int IfacesMap::speed(std::string dev)
{
    if (ifaceNum(dev) == -1) return MAX_RATE;

    return SysNetDevices.at(ifaceNum(dev))->Speed;
}

void IfacesMap::setFallbackRate(std::string dev, unsigned int rate)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->FallbackRate = rate;
}

void IfacesMap::addSection(std::string dev, std::string section)
{
    if (ifaceNum(dev) == -1) return;
    
    if (!aux::is_in_vector(SysNetDevices.at(ifaceNum(dev))->Sections, section)) SysNetDevices.at(ifaceNum(dev))->Sections.push_back(section);
}

bool IfacesMap::isInSections(std::string dev, std::string section) 
{
    if (ifaceNum(dev) == -1) return false;

    return (aux::is_in_vector(SysNetDevices.at(ifaceNum(dev))->Sections, section));
}

int IfacesMap::addToSectionsSpeedSum(std::string dev_name, unsigned int speed)
{
    Iface *dev;

    if (ifaceNum(dev_name) == -1) return -1;

    dev = SysNetDevices.at(ifaceNum(dev_name));
    
    if (dev->HtbDNWrapperClass) {
        if (!dev->Speed) { log->error(103, ""); return -1; }
        if (speed >= (dev->Speed - dev->SectionsSpeedSum - MIN_RATE)) { log->error (803, (dev_name + " speed " + aux::int_to_str(dev->Speed) + "b/s")); return -1; }
    }

    dev->SectionsSpeedSum += speed;

    return 0;
}

void IfacesMap::setTcFilterType(std::string dev, EnumTcFilterType tc_filter_type)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->TcFilterType = tc_filter_type;
}

EnumTcFilterType IfacesMap::tcFilterType(std::string dev)
{
    if (ifaceNum(dev) == -1) return U32;

    return SysNetDevices.at(ifaceNum(dev))->TcFilterType;
}

int IfacesMap::initHtbOnControlled()
{
    unsigned int fallback_rate;
    unsigned int dnwrapper_rate = 0;
    Iface *dev;

    if (sys->rtnlOpen() == -1) return -1;

    // Clear and create new HTB structure 
    for (unsigned int n=0; n < SysNetDevices.size(); n++) 
    {   
        dev = SysNetDevices.at(n);
        if (!dev->Controlled) continue;
            
        if (test->ifaceIsImq(dev->Name)) {
            if (system(std::string("ip link set " + dev->Name + " up").c_str()) == -1) { return -1; }
        }

        if (dev->HtbDNWrapperClass) {
            if (!dev->Speed) { sys->rtnlClose(); log->error(103, ""); return -1; }
            if (dev->Speed <= (dev->SectionsSpeedSum + dev->FallbackRate + MIN_RATE)) { sys->rtnlClose(); log->error (804, (dev->Name + " speed " + aux::int_to_str(dev->Speed) + "b/s")); return -1; }
            dnwrapper_rate = dev->Speed - (dev->SectionsSpeedSum + dev->FallbackRate);
        }  

        // Ugly hack!!
        if (system(std::string("tc qdisc del dev " + dev->Name + " root 2> /dev/null > /dev/null").c_str()) == -1) { sys->rtnlClose(); return -1; }
        //if (sys->tcQdisc(QOS_DEL, dev->Index, TC_H_ROOT, 1, HTB, 0) == -1) { sys->rtnlClose(); return -1; }
        if (sys->setQosQdisc(QOS_ADD, dev->Index, TC_H_ROOT, 1, HTB, dev->HtbFallbackId) == -1) { sys->rtnlClose(); return -1; }
        dev->QosInitialized = true;
        // HTB default - initial creation
        if (dev->HtbFallbackId) {
            fallback_rate = dev->SectionsSpeedSum;
            if (fallback_rate == 0) fallback_rate = dev->FallbackRate;
            if (sys->setQosClass(QOS_ADD, dev->Index, 0, dev->HtbFallbackId, fallback_rate, fallback_rate, 7, aux::compute_quantum(fallback_rate), 0 , 0) == -1) { sys->rtnlClose(); return -1; }
            if (sys->setQosQdisc(QOS_ADD, dev->Index, dev->HtbFallbackId, dev->HtbFallbackId, SFQ, 10) == -1) { sys->rtnlClose(); return -1; }
        }
        // HTB for safe do-not-shape and wrapper classes if exists
        if (dev->HtbDNWrapperClass) {
            if (sys->setQosClass(QOS_ADD, dev->Index, 0, HtbDNWrapperId, dnwrapper_rate, dnwrapper_rate, 7, aux::compute_quantum(dnwrapper_rate), 0 , 0) == -1 ) { sys->rtnlClose(); return -1; }
            if (sys->setQosQdisc(QOS_ADD, dev->Index, HtbDNWrapperId, HtbDNWrapperId, SFQ, 10) == -1 ) { sys->rtnlClose(); return -1; }
        }

        dev->WAMissLastU32Used = false;
    }

    sys->rtnlClose();

    return 0;
}

int IfacesMap::endUpHtbFallbackOnControlled()
{
    Iface *dev;

    if (sys->rtnlOpen() == -1) return -1;

    // HTB default - end up initialization
    for (unsigned int n=0; n < SysNetDevices.size(); n++) 
    { 
        dev = SysNetDevices.at(n);
        if (!dev->Controlled) continue;
        if (dev->HtbFallbackId) {
            if (sys->setQosClass(QOS_MOD, dev->Index, 0, dev->HtbFallbackId, dev->FallbackRate, dev->FallbackRate, 7, aux::compute_quantum(dev->FallbackRate), 0 , 0) == -1) { sys->rtnlClose(); return -1; }
        }
    }

    sys->rtnlClose(); 

    return 0;
}

unsigned int IfacesMap::htbDNWrapperId()
{
    return HtbDNWrapperId;
}

int IfacesMap::setFlowDirection(std::string dev, EnumFlowDirection flow_direction)
{
    if (ifaceNum(dev) == -1) return -1;

    if (SysNetDevices.at(ifaceNum(dev))->FlowDirection == UNSPEC) SysNetDevices.at(ifaceNum(dev))->FlowDirection = flow_direction;
    else if (SysNetDevices.at(ifaceNum(dev))->FlowDirection != flow_direction) return -1;

    return 0;
}

EnumFlowDirection IfacesMap::getFlowDirection(std::string dev)
{
    if (ifaceNum(dev) == -1) return UNSPEC;

    return SysNetDevices.at(ifaceNum(dev))->FlowDirection;
}

void IfacesMap::reportTcFilterU32Id(std::string dev, __u32 id)
{
    if (ifaceNum(dev) == -1) return;

    if (id < SysNetDevices.at(ifaceNum(dev))->TcFilterU32MinId) SysNetDevices.at(ifaceNum(dev))->TcFilterU32MinId = id;
    if (id > SysNetDevices.at(ifaceNum(dev))->TcFilterU32MaxId) SysNetDevices.at(ifaceNum(dev))->TcFilterU32MaxId = id;
}

__u32 IfacesMap::getTcFilterU32MinId(std::string dev)
{
    if (ifaceNum(dev) == -1) return 0;

    return SysNetDevices.at(ifaceNum(dev))->TcFilterU32MinId;
}

__u32 IfacesMap::getTcFilterU32MaxId(std::string dev)
{
    if (ifaceNum(dev) == -1) return 0;

    return SysNetDevices.at(ifaceNum(dev))->TcFilterU32MaxId;
}

void IfacesMap::setWAMissLastU32Used(std::string dev, bool used)
{
    if (ifaceNum(dev) == -1) return;

    SysNetDevices.at(ifaceNum(dev))->WAMissLastU32Used = used;
}

bool IfacesMap::getWAMissLastU32Used(std::string dev)
{
    if (ifaceNum(dev) == -1) return false;

    return SysNetDevices.at(ifaceNum(dev))->WAMissLastU32Used;
}


