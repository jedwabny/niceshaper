/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "class.h"

#include <cstdlib>

#include <iostream>
#include <string>
#include <vector>

#include "main.h"
#include "config.h"
#include "logger.h"
#include "filter.h"
#include "sys.h"
#include "ifaces.h"
#include "tests.h"
#include "aux.h"

NsClass::NsClass(std::string section_name, unsigned int section_id, unsigned int waitingroom_id, EnumFlowDirection flow_direction, unsigned int section_shape)
{
    SectionName = section_name;
    Header = "";
    Dev = "";
    Name = "";
    EsfqHash = "classic";
    TcQdiscEsfqAdd = "";
    NsClassType = STANDARD_CLASS;
    TcQdiscType = SFQ;
    FlowDirection = flow_direction;
    DevId = 0;
    ClassId = 0;
    Alive = 0;
    Hold = 30;
    NsLow = 0;
    NsCeil = 0;
    HtbParentId = section_id;
    WaitingRoomId = waitingroom_id;
    HtbRate = 0;
    HtbCeil = 0;
    HtbPrio = 5;
    HtbBurst = 0;
    HtbCBurst = 0;
    OldHtbCeil = 0;
    OldHtbRate = 0;
    RawBytesCurr = 0;
    RawBytesPrev = 0;
    Traffic = 0;
    SfqPerturb = 10;
    EsfqPerturb = 10;
    SectionShape = section_shape;
    Strict = 0.70;
    UseQosClass = true;
    UseQosFilter = true;
    StatusShowHtbCeil = true;
    StatusShowTraffic = true;
    Active = false;
    QosInitialized = false;
    // DnswStub related
    DnswStub = false;
    DnswStubBefore = 0;
    DnswStubTcFiltersNum = 0;
}

NsClass::~NsClass()
{
    if (DnswStub) return;

    for (unsigned int n=0; n<TcFilters.size(); n++) delete TcFilters.at(n);

    TcFilters.clear();
}

void NsClass::setAsDnswStub()
{
    DnswStub = true;
    NsClassType = WRAPPER;
}

int NsClass::store(std::string buf)
{
    std::string option, param, value;
    
    if (buf.empty()) return 0;      

    option = aux::awk(buf, 1);  
    param = aux::awk(buf, 2);  
    value = aux::awk(buf, 3);  
    
    if ((option == "class") || (option == "class-virtual")) { 
        Header = buf;
        Dev = aux::trim_dev(aux::awk(buf, 3));
        Name = aux::awk(buf, 4);
        if (!Name.size() || aux::awk(buf, 5).size()) { log->error (SectionName, 24, buf); return -1; }
        if (!ifaces->isValidSysDev(Dev)) { log->error (SectionName, 16, buf); return -1; }
        DevId = ifaces->index(Dev);
        if (option == "class") NsClassType = STANDARD_CLASS;
        else if (option == "class-virtual") NsClassType = VIRTUAL;   
    } 
    else if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
        Header = buf;
        Dev = aux::trim_dev(aux::awk(buf, 2));
        Name = aux::awk(buf, 3);
        if (!Name.size() || aux::awk(buf, 4).size()) { log->error (SectionName, 24, buf); return -1; }
        if (!ifaces->isValidSysDev(Dev)) { log->error (SectionName, 16, buf); return -1; }
        DevId = ifaces->index(Dev);
        if (option == "class-wrapper") NsClassType = WRAPPER;
        else if (option == "class-do-not-shape") NsClassType = DONOTSHAPE;
    }
    else if (option == "_classid_") { 
        ClassId = aux::str_to_uint (param); 
        if (sys->computeQosClassId(1, ClassId, &QosClassId) == -1) return -1;
    }
    else if (option == "_dnswstub-before_") {
        DnswStubBefore = aux::str_to_uint (param);
    }
    else if (option == "match") {
        if (!DnswStub) TcFilters.push_back(new TcFilter (SectionName, Header, buf, WaitingRoomId, FlowDirection));
        else DnswStubTcFiltersNum++;
    }
    else if (option == "low") {
        NsLow = aux::unit_convert (param, BITS );
    }
    else if (option == "ceil") {
        NsCeil = HtbCeil = aux::unit_convert (param, BITS );
    }
    else if (option == "rate") { 
        NsLow = NsCeil = HtbCeil = aux::unit_convert (param, BITS);
    } 
    else if (option == "strict") {
        Strict = aux::str_to_double(param)/100;
    }
    else if (option == "hold") {
        Hold = aux::str_to_uint (param);
    }
    else if (option == "htb") {
        if (param == "scheduler") {
            if (value == "sfq") TcQdiscType = SFQ;
            else if (value == "esfq") TcQdiscType = ESFQ;
            else if (value == "no") TcQdiscType = NOQDISC;
            else { 
                log->error (SectionName, 17, buf); 
                return -1; 
            }
        }   
        else if (param == "prio") HtbPrio = aux::str_to_uint (value);
        else if (param == "burst") HtbBurst = aux::unit_convert (value, BYTES);
        else if (param == "cburst") HtbCBurst = aux::unit_convert (value, BYTES);
        else {
            log->error (SectionName, 11, buf);
            return -1;
        }        
    }
    else if (option == "sfq")
    {
        if (param == "perturb") SfqPerturb = aux::str_to_uint(value);  
        else { 
            log->error (SectionName, 11, buf); 
            return -1; 
        }   
    }
    else if (option == "esfq") {
        if (param == "hash") {
            if (value == "classic") EsfqHash = "classic";
            else if (value == "dst") EsfqHash = "dst";
            else if (value == "src") EsfqHash = "src";
            else { 
                log->error (SectionName, 11, buf); 
                return -1; 
            }
        }
        else if (param == "perturb") EsfqPerturb = aux::str_to_uint(value);  
        else { 
            log->error (SectionName, 11, buf); 
            return -1; 
        }
    }
    else if (option == "alter") {
        Alter.store(buf);
    }
    else if (option == "quota") {
        Quota.store(buf);
    }
    // Deprecated directives
    else if (option == "imq") {
        if (param == "autoredirect") { 
            log->error(SectionName, 150, buf); 
            return -1; 
        }
        else { 
            log->error(SectionName, 11, buf); 
            return -1; 
        }
    }
    else if (option == "type") {
        log->error(SectionName, 152, buf);
        return -1;
    }
    
    if (log->getErrorLogged()) return -1;

    if (option != "match") {
        for (unsigned int n=0; n<TcFilters.size(); n++) {
            if (TcFilters.at(n)->store(buf) == -1) return -1;
        }
    }

    return 1;
}

int NsClass::recoverQos()
{
    DevId = ifaces->index(Dev);
    Active = false;
    QosInitialized = false;

    for (unsigned int n = 0; n < TcFilters.size(); n++) {
        TcFilters.at(n)->recoverQos();
    }

    return 0;
}

bool NsClass::getIptRequired() 
{
    if (DnswStub) {
        if (getIptRequiredToOperate() || getIptRequiredToCheckActivity() || getIptRequiredToCheckTraffic()) return true;
        else return false;
    }

    return TcFilters.at(0)->getIptRequired();

}
bool NsClass::getIptRequiredToOperate()
{
    if (DnswStub) {
        if (ifaces->tcFilterType(Dev) == FW) return true;
        else if (test->ifaceIsImq(Dev) && config->getImqAutoRedirect()) return true;
        else return false;
    }

    return TcFilters.at(0)->getIptRequiredToOperate();
}

bool NsClass::getIptRequiredToCheckActivity() 
{
    if (DnswStub) {   
        if (ifaces->tcFilterType(Dev) == FW) return true;
        else if (sys->getMissU32Perf()) return true;
        else return false;
    }

    return TcFilters.at(0)->getIptRequiredToCheckActivity();
}

bool NsClass::getIptRequiredToCheckTraffic() 
{
    if (DnswStub) {
        if ((NsClassType == DONOTSHAPE) && config->getStatusShowDoNotShape()) return true;
        else return false;
    }

    return TcFilters.at(0)->getIptRequiredToCheckTraffic();
}

int NsClass::validateParams()
{
    if (NsClassType == STANDARD_CLASS) {
        StatusShowHtbCeil = true; StatusShowTraffic = true;
        UseQosClass = true; UseQosFilter = true;
    }
    else if (NsClassType == VIRTUAL) {
        StatusShowHtbCeil = false; StatusShowTraffic = true;
        UseQosClass = false; UseQosFilter = false;
        NsLow = 0; NsCeil = 0; HtbRate = 0; HtbCeil = 0;
    } 
    else if (NsClassType == WRAPPER) {
        StatusShowHtbCeil = true; StatusShowTraffic = true;
        UseQosClass = true; UseQosFilter = true;
        if (!NsCeil) { log->error(SectionName, 814, Header); return -1; }
        NsLow = HtbRate = HtbCeil = NsCeil;
        HtbParentId = ifaces->htbDNWrapperId();
    }
    else if (NsClassType == DONOTSHAPE) {
        StatusShowHtbCeil = false; StatusShowTraffic = true;
        UseQosClass = false; UseQosFilter = true;
        NsLow = 0; NsCeil = 0; HtbRate = 0; HtbCeil = 0;
    } 

    if (getTcFiltersNum() == 0) { log->error (SectionName, 22, Header); return -1; }

    if (DnswStub) return 0;

    if ((NsClassType == STANDARD_CLASS) || (NsClassType == WRAPPER)) {
        if ((NsLow > MAX_RATE) || (NsLow && (NsLow < MIN_RATE))) { log->error (SectionName, 806); return -1; }
        if ((NsCeil > MAX_RATE) || (NsCeil && (NsCeil < MIN_RATE))) { log->error (SectionName, 806); return -1; }
        if ((Strict < 0) || (Strict > 1)) { log->error(SectionName, 807); return -1; }
        if (!NsLow) NsLow = MIN_RATE;
        if (!NsCeil) NsCeil = SectionShape; 
        if ((NsClassType == STANDARD_CLASS) && (NsCeil > SectionShape)) NsCeil = SectionShape;
        if (NsLow > NsCeil) NsLow = NsCeil;
    }

    for (unsigned int n=0; n<TcFilters.size(); n++) {
        if (TcFilters.at(n)->validateParams() == -1) return -1;
    }
 
    return 0;
}

int NsClass::prepareQosClass()
{
    if (NsLow > NsCeil) NsCeil = NsLow;
    if (!UseQosClass) return 0;

    if (TcQdiscType == ESFQ) {
        TcQdiscEsfqAdd = "tc qdisc add dev " + Dev + " parent 1:" + aux::int_to_hex(ClassId) + " handle " + aux::int_to_hex(ClassId) + ": esfq perturb " + aux::int_to_str(EsfqPerturb) + " hash " + EsfqHash;
    }

    return 1;
}

int NsClass::prepareAndAddQosFilters()
{
    bool flow_to_target = false;

    if (!UseQosFilter) return 0;

    if (NsClassType == STANDARD_CLASS) flow_to_target = false;
    else flow_to_target = true;
    
    for (unsigned int n = 0; n < TcFilters.size(); n++)
    {
        if (TcFilters.at(n)->prepareTcFilter() == -1) return -1;
        if (TcFilters.at(n)->add(flow_to_target) == -1) return -1;
        if (TcFilters.at(n)->tcFilterType() == U32) ifaces->reportTcFilterU32Id(Dev, TcFilters.at(n)->tcFilterId());
        if (TcFilters.at(0)->tcFilterType() == FW) n=TcFilters.size();
    }

    return 1;
}

int NsClass::proceedQosFilterHits(__u32 qos_filter_id, __u64 qos_filter_hits)
{
    if (!UseQosFilter) return -1;
    if (getIptRequiredToCheckActivity()) return -1;
    if (QosInitialized) return -1;

    for (unsigned int n = 0; n < TcFilters.size(); n++) {
        if (TcFilters.at(n)->tcFilterId() == qos_filter_id) {
            if (qos_filter_hits) {
                proceedReceiptTraffic(64); // Can't get bytes from U32 filter hits
                return 1;
            }
            return 0;
        }
    }

    return -1;
}

int NsClass::proceedReceiptTraffic(__u64 raw_bytes_curr)
{
    RawBytesPrev = RawBytesCurr;
    RawBytesCurr = raw_bytes_curr;   

    return 0;
}

int NsClass::proceedReceiptIptCountersSum(__u64 ipt_counters_sum)
{
    RawBytesIptPrev = ipt_counters_sum;

    return 0;
}

int NsClass::proceedReceiptedTraffic(struct timeval tv_curr, double round_duration)
{
    __u64 round_bits = 0;

    round_bits = (RawBytesCurr - RawBytesPrev) << 3;

    if (NsClassType == STANDARD_CLASS) {    
        Quota.totalize(round_bits);
        proceedTriggers (tv_curr);
    }

    if (round_bits) {
        Active = true;
        Alive = tv_curr.tv_sec;
        if (NsClassType == STANDARD_CLASS) {
            if (QosInitialized) {
                OldHtbRate = HtbRate;
                OldHtbCeil = HtbCeil;
            }
            else {
                OldHtbRate = HtbRate = MIN_RATE;
                OldHtbCeil = HtbCeil = NsCeil;
                RawBytesCurr = 0;
                RawBytesPrev = 0;
            }
        }
    }
    else {
        if ((NsClassType == STANDARD_CLASS) && QosInitialized) {
            OldHtbRate = HtbRate;
            OldHtbCeil = HtbCeil;
        }
        if (Active && Hold && ((tv_curr.tv_sec - Alive) >= Hold)) {
            if (NsClassType == STANDARD_CLASS) {
                RawBytesCurr = 0;
                RawBytesPrev = 0;
                if (getIptRequiredToCheckActivity()) RawBytesCurr = RawBytesIptPrev;
            }
            Active = false;
       }
    }

    Traffic = static_cast<unsigned int>(static_cast<double>(round_bits)/static_cast<double>(round_duration));

    return 0;
}

unsigned int NsClass::trafficPrognosed()
{
    if (Traffic >= HtbCeil) return HtbCeil; 
    else return Traffic;

    return Traffic;
}

void NsClass::computeGrade()
{
    unsigned int higher_resp_point = NsLow + (NsCeil-NsLow)*Strict;

    if (Traffic <= NsLow) GradeForReducing = 0;    
    else if (Traffic <= higher_resp_point) GradeForReducing=(0.5/Strict)*(static_cast<double>(Traffic-NsLow)/static_cast<double>(NsCeil-NsLow));
    else if (Traffic < NsCeil) GradeForReducing=(0.5/(1-Strict))*(static_cast<double>(Traffic-NsLow)/static_cast<double>(NsCeil-NsLow)-Strict)+0.5;
    else GradeForReducing = 1;
}

int NsClass::add()
{
    unsigned int quantum = aux::compute_quantum(HtbCeil);
    bool flow_to_target = true;

    if (UseQosClass) {
       if (sys->setQosClass(QOS_ADD, DevId, HtbParentId, ClassId, HtbRate, HtbCeil, HtbPrio, quantum, HtbBurst, HtbCBurst) == -1) return -1;
       if (TcQdiscType == ESFQ) {
           if (system(TcQdiscEsfqAdd.c_str()) == -1) return -1;
       }
       else if (TcQdiscType != NOQDISC) {
           if (sys->setQosQdisc(QOS_ADD, DevId, ClassId, ClassId, TcQdiscType, SfqPerturb) == -1) return -1;
       }
    }

    if (UseQosFilter) {
        for (unsigned int i = 0; i < TcFilters.size(); i++) {
            if (TcFilters.at(i)->del() == -1) return -1;
            if (TcFilters.at(i)->add(flow_to_target) == -1) return -1;
            if (TcFilters.at(0)->tcFilterType() == FW) i=TcFilters.size();
       }
    }

    QosInitialized = true;

    return 1;
}

int NsClass::addWAMissLastU32()
{
    if (!UseQosFilter) return -1;
    if (!TcFilters.size()) return -1;
    if (ifaces->tcFilterType(Dev) == FW) return -1;
           
    return TcFilters.back()->addWAMissLastU32();
}

int NsClass::del()
{
    unsigned int quantum = aux::compute_quantum(HtbCeil);
    bool flow_to_target = false;

    if (UseQosFilter)
    {
        for (unsigned int i = 0; i < TcFilters.size(); i++) {
            if (TcFilters.at(i)->del() == -1) return -1;
            if (TcFilters.at(i)->add(flow_to_target) == -1) return -1;
            if (TcFilters.at(0)->tcFilterType() == FW) i=TcFilters.size();
        }
    }

    if (UseQosClass) {
        if (TcQdiscType != NOQDISC) {
            if (sys->setQosQdisc(QOS_DEL, DevId, ClassId, ClassId, TcQdiscType, 0)== -1) return -1;
        }
        if (sys->setQosClass(QOS_DEL, DevId, HtbParentId, ClassId, HtbRate, HtbCeil, HtbPrio, quantum, HtbBurst, HtbCBurst) == -1) return -1;
    }

    QosInitialized = false;

    return 1;
}

int NsClass::applyChanges(unsigned int working_classes)
{
    unsigned int quantum = aux::compute_quantum(HtbCeil);

    if (NsClassType != STANDARD_CLASS) return 0;

    if (Active && !QosInitialized) {
        if (add() == -1) return -1;
    }
    else if (!Active && QosInitialized) {
        if (del() == -1) return -1;
    }

    if (!Active) return 0;

    if (HtbCeil > NsCeil) HtbCeil = NsCeil;
    if (HtbCeil < NsLow) HtbCeil = NsLow;

    HtbRate = SectionShape / working_classes; 

    if (HtbRate > HtbCeil) HtbRate = HtbCeil;

    if ((HtbRate == OldHtbRate) && (HtbCeil == OldHtbCeil)) return 0;

    if (sys->setQosClass(QOS_MOD, DevId, HtbParentId, ClassId, HtbRate, HtbCeil, HtbPrio, quantum, HtbBurst, HtbCBurst) == -1) return -1;

    return 0;
}

int NsClass::proceedTriggers (struct timeval cttime)
{
    unsigned int dmin;
    unsigned int wday;
    unsigned int mday;
    bool mday_last = false;
    int trigger_state;
    struct tm *ltime;

    ltime = localtime(&cttime.tv_sec);
    dmin = ltime->tm_hour*60+ltime->tm_min;
    wday = ltime->tm_wday;
    mday = ltime->tm_mday;
    cttime.tv_sec += 86400;
    ltime = localtime(&cttime.tv_sec);
    if (ltime->tm_mday == 1) mday_last = true;

    // Check alter trigger
    trigger_state = Alter.check (dmin);
    if ((trigger_state == 1) || (trigger_state == 2)) {
        // Replace (A<=>Q);
        if (Quota.isActive() && Alter.isUseNsLow() && Quota.isUseNsLow()) aux::shift (Alter.getTriggerNsLowRef(), Quota.getTriggerNsLowRef());
        else if (Quota.isActive() && Alter.isUseNsCeil() && Quota.isUseNsCeil()) aux::shift (Alter.getTriggerNsCeilRef(), Quota.getTriggerNsCeilRef());
        else {
            // Replace (A<=>0);
            if (Alter.isUseNsLow()) aux::shift (Alter.getTriggerNsLowRef(), NsLow);
            if (Alter.isUseNsCeil()) aux::shift (Alter.getTriggerNsCeilRef(), NsCeil);
        }
    }

    // Check quota trigger
    trigger_state = Quota.check (dmin, wday, mday, mday_last);
    if ((trigger_state == 1) || (trigger_state == 2)) {
        // Replace (Q<=>0)
        if (Quota.isUseNsLow()) aux::shift (Quota.getTriggerNsLowRef(), NsLow);
        if (Quota.isUseNsCeil()) aux::shift (Quota.getTriggerNsCeilRef(), NsCeil);
    }

    return 0;
}

std::string NsClass::status()
{
    std::string result = "";

    if ((config->getStatusShowClasses() == SC_ALL)
            || ((config->getStatusShowClasses() == SC_ACTIVE) && Traffic)
            || ((config->getStatusShowClasses() == SC_WORKING) && Active)) 
    {
        if (NsClassType == VIRTUAL) result = "^" + Name + "^";
        else if (NsClassType == WRAPPER) result = "|" + Name + "|";
        else if (NsClassType == DONOTSHAPE) result = "!" + Name + "!";
        else result = Name;

        if (StatusShowHtbCeil) {
            if (!DnswStub) result += " " + aux::int_to_str(HtbCeil) + " " + aux::int_to_str(OldHtbCeil);
            else result += " " + aux::int_to_str(NsCeil) + " " + aux::int_to_str(NsCeil);
        }
        else result += " - -";

        if (StatusShowTraffic) result += " " + aux::int_to_str(Traffic);
        else result += " -";
    }

    return result;
}

std::string NsClass::dumpQuotaCounters()
{
    std::string counters = Quota.dumpCounters();

    if (counters.size()) return (Name + " " + counters);
    return "";
}

void NsClass::setQuotaCounters(unsigned int counter_day, unsigned int counter_week, unsigned int counter_month)
{
    Quota.setCounters (counter_day, counter_week, counter_month);

    return;
}

unsigned int NsClass::getTcFiltersNum() 
{
    if (DnswStub) return DnswStubTcFiltersNum;

    return TcFilters.size(); 
}

__u32 NsClass::getTcFilterU32MaxId()
{
    return TcFilters.back()->tcFilterId();
}

