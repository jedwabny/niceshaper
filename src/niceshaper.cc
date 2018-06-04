/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "niceshaper.h"

#include <sys/time.h>
#include <stdlib.h>
#include <cstdio>

#include <vector>
#include <string>
#include <iostream>

#include "main.h"
#include "class.h"
#include "config.h"
#include "logger.h"
#include "aux.h"
#include "sys.h"
#include "ifaces.h"
#include "tests.h"

NiceShaper::NiceShaper(std::string section_name, unsigned int section_id, unsigned int waitingroom_id, bool sao_container)
{
    SectionName = section_name;
    SectionId = section_id;
    WaitingRoomId = waitingroom_id;
    SAOContainter = sao_container;
    Reload = 2 * 1000 * 1000; // 2 seconds
    CrossBar = 1;
    SectionHtbCeil = 0;
    SectionShape = 0;
    SectionHtbBurst = 0;
    SectionHtbCBurst = 0;
    SectionTraffic = 0;
    Working = 0;
    FlowDirection = UNSPEC;
    IptRequired = false;
    IptRequiredToCheckActivity = false;
    IptRequiredToCheckTraffic = false;
    DnswDoNotShape = false;
    DnswWrapper = false;
}

NiceShaper::~NiceShaper()
{
    for (unsigned int n=0; n<NsClasses.size(); n++) delete NsClasses.at(n); 

    NsClasses.clear();
}

int NiceShaper::init(std::vector <std::string> &fpv_conffile, std::vector <std::string> &fpv_classfile)
{
    std::string buf;
    std::string option, param, value;
    std::string iface;
    std::vector <std::string> fpv_myclasses, fpv_myclasses_dnswstubs;
    std::vector <std::string>::iterator fpvi, fpvi_begin, fpvi_end, fpvi_tmp; 
    unsigned int dnsw_before;
    bool mydatablock, mydatablockdnswstubs;
    unsigned int max_htb_burst = 0;
    unsigned int max_htb_cburst = 0;
    NsClass* nsclass_template;    
    std::string nsclass_name;
    std::vector <std::string> nsclasses_registered;

    if (!SAOContainter) {
        /* reading section config */
        if (aux::fpv_section_i(fpvi_begin, fpvi_end, fpv_conffile, SectionName) == -1 ) {
            return -1;
        }

        // section directives
        fpvi = fpvi_begin;  
        while (fpvi <= fpvi_end)
        {
            option = aux::awk( *fpvi, 1 );
            param = aux::awk( *fpvi, 2 );
            value = aux::awk( *fpvi, 3 );
            if (option == "match")
            {
                log->error(SectionName, 861, *fpvi);
            }        
            else if (option == "section") {
                if (param == "speed") {
                    SectionHtbCeil = aux::unit_convert( value, BITS );
                    if (( SectionHtbCeil > MAX_RATE ) || ( SectionHtbCeil < MIN_RATE )) log->error(SectionName, 806, *fpvi);
                }
                else if (param == "shape") {
                    SectionShape = aux::unit_convert( value, BITS );
                    if ((SectionShape > MAX_RATE) || (SectionShape < MIN_RATE)) log->error(SectionName, 806, *fpvi);
                }
                else if (param == "htb-burst") {
                    SectionHtbBurst = aux::unit_convert (value, BYTES);
                }
                else if (param == "htb-cburst") {
                    SectionHtbCBurst = aux::unit_convert (value, BYTES);
                }
                else { log->error(SectionName, 11, *fpvi); }
            } 
            else if (option == "reload") 
            {  
                Reload = static_cast<unsigned int>(aux::str_to_double(param)*1000*1000);
                if ((Reload < 100*1000) || (Reload > (60*1000*1000))) {
                    log->error(SectionName, 13, *fpvi);
                    return -1;
                }
            }
            else if (option == "mode")
            {
                if (param == "download") FlowDirection = DWLOAD;
                else if (param == "upload") FlowDirection = UPLOAD;
                else { log->error(SectionName, 14, *fpvi ); return -1; }
            }
            else if (option == "debug")
            {
                if (param == "iptables") log->error(SectionName, 151, *fpvi);
            }

            if (log->getErrorLogged()) return -1;

            fpvi++;
        }

        if (!SectionHtbCeil) log->error(SectionName, 19, ""); 
        if (!SectionShape) log->error(SectionName, 20, ""); 
        if (FlowDirection == UNSPEC) log->error(SectionName, 21, "");
        if (SectionShape > SectionHtbCeil ) log->error(SectionName, 40, "");
    }
    else {
        SectionHtbCeil = MAX_RATE;
        SectionShape = MAX_RATE;
    }

    /* Initialize template object with default values */
    nsclass_template = new NsClass(SectionName, SectionId, WaitingRoomId, FlowDirection, SectionShape);

    if (!SAOContainter) {
        // Classes defaults
        fpvi = fpvi_begin;  
        while (fpvi <= fpvi_end)
        {
            option = aux::awk( *fpvi, 1 );
            param = aux::awk( *fpvi, 2 );
            value = aux::awk( *fpvi, 3 );
            if ((option == "low") || (option == "ceil") || (option == "rate") || (option == "strict") || (option == "hold")) {
                if (nsclass_template->store(*fpvi) == -1) return -1;
            }     
            else if ((option == "htb") || (option == "sfq") || (option == "esfq")) {
                if (nsclass_template->store(*fpvi) == -1) return -1;
            }    
            else if ((option == "alter") || (option == "quota")) {
                if (nsclass_template->store(*fpvi) == -1) return -1;
            }
            // Deprecated directives
            else if ((option == "imq") || (option == "type")) {
                nsclass_template->store(*fpvi);
            }

            if (log->getErrorLogged()) return -1;

            fpvi++;
        }
    }

    mydatablock = false;
    mydatablockdnswstubs = false;
    dnsw_before = 0; 
    fpvi=fpv_classfile.begin();
    while (fpvi != fpv_classfile.end()) 
    {
        option = aux::awk(*fpvi, 1);
        if (!SAOContainter) {
            if ((option == "class") || (option == "class-virtual")) {
                if (aux::awk(*fpvi, 2) == SectionName) {
                    mydatablock = true;
                    mydatablockdnswstubs = false;
                    dnsw_before++;
                }
                else {
                    mydatablock = false;
                    mydatablockdnswstubs = false;
                }
            }
            else if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
                mydatablock = false;
                mydatablockdnswstubs = true;
            }
        }
        else {
            if ((option == "class-wrapper") || (option == "class-do-not-shape")) mydatablock = true;
            else if ((option == "class") || (option == "class-virtual")) mydatablock = false;
        }

        if (mydatablock) {
            fpv_myclasses.push_back(*fpvi);
        }
        else if (mydatablockdnswstubs) {
            fpv_myclasses_dnswstubs.push_back(*fpvi);       
            if ((option == "class-wrapper") || (option == "class-do-not-shape")) fpv_myclasses_dnswstubs.push_back("_dnswstub-before_ " + aux::int_to_str(dnsw_before));
        }

        fpvi++;
    }

    if (!fpv_myclasses.size()) {
        if (SAOContainter) return 0;
        else {
            log->error(SectionName, 23, "");
            return -1;
        }
    }

    /* Initialize NsClass objects, using template object and extra parameters */     
    fpvi=fpv_myclasses.begin();
    while (fpvi != fpv_myclasses.end())
    {
        option = aux::awk (*fpvi, 1);
        param = aux::awk (*fpvi, 2);
        if (aux::is_in_vector(config->ProperClassesTypes, option)) {
            // Create class object
            NsClasses.push_back (new NsClass(*nsclass_template));
            // Completing section interfaces and class names
            if ((option == "class") || (option == "class-virtual")) {
                iface = aux::trim_dev(aux::awk(*fpvi, 3));
                nsclass_name = aux::awk(*fpvi, 4);
                if ((option == "class-virtual") && (test->ifaceIsImq(iface))) { log->error (SectionName, 864, *fpvi); return -1; }
                if (ifaces->setFlowDirection(iface, FlowDirection) == -1) { log->error (SectionName, 866, *fpvi); return -1; }
            }
            else if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
                iface = aux::trim_dev(aux::awk(*fpvi, 2));
                nsclass_name = aux::awk(*fpvi, 3);
            }
            if (!ifaces->isValidSysDev(iface)) { log->error (SectionName, 16, *fpvi); return -1; }
            if (!aux::is_in_vector(SectionIfaces, iface)) SectionIfaces.push_back(iface);
            if (aux::is_in_vector(nsclasses_registered, nsclass_name)) { log->error (SectionName, 863, *fpvi); return -1; }
            nsclasses_registered.push_back(nsclass_name);
        }
        if (NsClasses.back()->store(*fpvi) == -1) return -1;
        fpvi++; 
    } 

    if (!SAOContainter && fpv_myclasses_dnswstubs.size()) {
        mydatablockdnswstubs = false;
        fpvi=fpv_myclasses_dnswstubs.begin();
        while (fpvi != fpv_myclasses_dnswstubs.end())
        {
            option = aux::awk (*fpvi, 1);
            if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
                if (!aux::is_in_vector(SectionIfaces, aux::awk(*fpvi, 2))) {
                    mydatablockdnswstubs = false;
                    fpvi++;
                    continue;
                }
                mydatablockdnswstubs = true;
                NsClassesDnswStubs.push_back(new NsClass(SectionName, SectionId, WaitingRoomId, FlowDirection, SectionShape));
                NsClassesDnswStubs.back()->setAsDnswStub();
                if (option == "class-wrapper") DnswWrapper = true;
                else if (config->getStatusShowDoNotShape() && (option == "class-do-not-shape")) DnswDoNotShape = true;
            }
            if (mydatablockdnswstubs) {
                if (NsClassesDnswStubs.back()->store(*fpvi) == -1) return -1;
            }

            fpvi++;
        }
    }

    delete nsclass_template;  

    for (unsigned int n=0; n < NsClasses.size(); n++) {
        if (NsClasses.at(n)->validateParams() == -1) return -1;
        if (NsClasses.at(n)->prepareQosClass() == -1) return -1;
        if (NsClasses.at(n)->htbBurst() > max_htb_burst) max_htb_burst = NsClasses.at(n)->htbBurst();
        if (NsClasses.at(n)->htbCBurst() > max_htb_cburst) max_htb_cburst = NsClasses.at(n)->htbCBurst();
        // Check for iptables requirement
        if (!IptRequired) IptRequired = NsClasses.at(n)->getIptRequired();
        if (!IptRequiredToCheckActivity) IptRequiredToCheckActivity = NsClasses.at(n)->getIptRequiredToCheckActivity();
        if (!IptRequiredToCheckTraffic) IptRequiredToCheckTraffic = NsClasses.at(n)->getIptRequiredToCheckTraffic();
   }

    for (unsigned int n=0; n < NsClassesDnswStubs.size(); n++) {
        if (NsClassesDnswStubs.at(n)->validateParams() == -1) return -1;
        if (!IptRequired) IptRequired = NsClassesDnswStubs.at(n)->getIptRequired();
        if (!IptRequiredToCheckActivity) IptRequiredToCheckActivity = NsClassesDnswStubs.at(n)->getIptRequiredToCheckActivity();
        if (!IptRequiredToCheckTraffic) IptRequiredToCheckTraffic = NsClassesDnswStubs.at(n)->getIptRequiredToCheckTraffic();
    }

    if (SectionHtbBurst && max_htb_burst && (SectionHtbBurst < max_htb_burst)) { sys->rtnlClose(); log->error (SectionName, 802); return -1; }
    else if (!SectionHtbBurst && max_htb_burst) SectionHtbBurst = max_htb_burst;

    if (SectionHtbCBurst && max_htb_cburst && (SectionHtbCBurst < max_htb_cburst)) { sys->rtnlClose(); log->error (SectionName, 802); return -1; }
    else if (!SectionHtbCBurst && max_htb_cburst) SectionHtbCBurst = max_htb_cburst;

    if (initQos() == -1) return -1;
   
    return 0;
}

int NiceShaper::initQos()
{
    std::string iface;

    // Initialize common HTB classes and filters
    if (sys->rtnlOpen() == -1) { return -1; }

    if (!SAOContainter) {
        log->onTerminal ("");

        for (unsigned int n=0; n<SectionIfaces.size(); n++) {
            iface = SectionIfaces.at(n);

            if (!ifaces->isValidSysDev(iface)) { sys->rtnlClose(); log->error (SectionName, 16, iface); return -1; }

            if (sys->setQosClass(QOS_ADD, ifaces->index(iface), 0, SectionId, SectionHtbCeil, SectionHtbCeil, 5, aux::compute_quantum(SectionHtbCeil), SectionHtbBurst, SectionHtbCBurst) == -1) { sys->rtnlClose(); return -1; }
            if (sys->setQosClass(QOS_ADD, ifaces->index(iface), SectionId, WaitingRoomId, (SectionHtbCeil-SectionShape), (SectionHtbCeil-SectionShape), 5, aux::compute_quantum((SectionHtbCeil-SectionShape)), 0, 0) == -1) { sys->rtnlClose(); return -1; }
            if (sys->setQosQdisc(QOS_ADD, ifaces->index(iface), WaitingRoomId, WaitingRoomId, SFQ, 10) == -1) { sys->rtnlClose(); return -1; }
        }
    }

    // Initialize basics for classes
    for (unsigned int n=0; n<NsClasses.size(); n++) {
        if (NsClasses.at(n)->prepareAndAddQosFilters() == -1) { sys->rtnlClose(); return -1; }
        if (NsClasses.at(n)->type() == WRAPPER) {
            if (NsClasses.at(n)->add() == -1) { sys->rtnlClose();  return -1; }
        }
    }

    sys->rtnlClose();

    return 0;
}

int NiceShaper::recoverQos()
{
    for (unsigned int n=0; n<NsClasses.size(); n++) {
        NsClasses.at(n)->recoverQos();
    }
   
    if (initQos() == -1) return -1;

    return 0;
}

EnumFlowDirection NiceShaper::getFlowDirection() 
{ 
    return FlowDirection; 
}

void NiceShaper::setIptRequired(bool required)
{
    IptRequired = required;
}

void NiceShaper::setIptRequiredToCheckActivity(bool required)
{
    IptRequiredToCheckActivity = required;
}

bool NiceShaper::getIptRequired() 
{ 
    return IptRequired; 
}

bool NiceShaper::getIptRequiredToCheck() 
{ 
    if (IptRequiredToCheckActivity || IptRequiredToCheckTraffic) return true; 

    return false; 
}

int NiceShaper::receiptIptTraffic (std::vector <__u64> &ipt_ordered_counters, std::vector <__u64> &ipt_ordered_counters_dnsw)
{
    IptOrderedCounters.clear();
    IptOrderedCountersDnsw.clear();

    for (unsigned int n=0; n < ipt_ordered_counters.size(); n++) {
        IptOrderedCounters.push_back(ipt_ordered_counters.at(n));
    }

    if (DnswDoNotShape) {
        for (unsigned int n=0; n < ipt_ordered_counters_dnsw.size(); n++) {
            IptOrderedCountersDnsw.push_back(ipt_ordered_counters_dnsw.at(n));
        }
    }

    return 0;
}

int NiceShaper::qosCheckClassesBytes()
{
    NsClass *iterclass;
    std::string iface;
    __u32 qos_class_id;
    __u64 qos_class_bytes;
    bool proceeded;

    for (unsigned int n=0; n < SectionIfaces.size(); n++) {
        iface = SectionIfaces.at(n);
        if (sys->qosCheck(ifaces->index(iface), QOS_CLASS) == -1) { return -1; }
    }

    for (unsigned int n=0; n < (NsClasses.size() + NsClassesDnswStubs.size()); n++) {
        proceeded = false;
        if ((NsClasses.size()) && (n < NsClasses.size())) {
            iterclass = NsClasses.at(n);
            if (!iterclass->getUseQosClass()) continue;
            if (!iterclass->getQosInitialized()) continue;
            if (iterclass->getIptRequiredToCheckTraffic()) continue;
        }  
        else {
            if (!DnswWrapper) {
                n = (NsClasses.size() + NsClassesDnswStubs.size());
                continue;
            }
            iterclass = NsClassesDnswStubs.at(n-NsClasses.size());
            if (iterclass->type() != WRAPPER) continue;
        }
        for (unsigned int m=0; m < sys->QosClassesBytes.size(); m++) {
            qos_class_id = sys->QosClassesBytes.at(m)->QosClassId;
            qos_class_bytes = sys->QosClassesBytes.at(m)->Bytes;
            if (qos_class_id == iterclass->qosClassId()) {
                iterclass->proceedReceiptTraffic(qos_class_bytes);
                m=sys->QosClassesBytes.size();
                proceeded = true;
            }
        }
        if (!proceeded) {
            log->error(SectionName, 501);
            log->setReqRecoverQos(true);
            return -1;
        }
    }

    return 0;
}

int NiceShaper::qosCheckFiltersHits()
{
    std::string iface;
    __u32 qos_filter_id;
    __u64 qos_filter_hits;
    int res;
    unsigned int proceeded_filters_hits;

    for (unsigned int n=0; n < SectionIfaces.size(); n++) {
        iface = SectionIfaces.at(n);
        if (sys->qosCheck(ifaces->index(iface), QOS_FILTER) == -1) return -1;
    }

    for (unsigned int n=0; n < NsClasses.size(); n++) {
        iface = NsClasses.at(n)->getDev();
        proceeded_filters_hits = 0;
        if (!NsClasses.at(n)->getUseQosFilter()) continue;
        if (NsClasses.at(n)->getIptRequiredToCheckActivity()) continue;
        if (NsClasses.at(n)->getQosInitialized()) continue;
        for (unsigned int m=0; m < sys->QosFiltersHits.size(); m++) {
            qos_filter_id = sys->QosFiltersHits.at(m)->QosFilterId;
            qos_filter_hits = sys->QosFiltersHits.at(m)->Hits;
            res = NsClasses.at(n)->proceedQosFilterHits(qos_filter_id, qos_filter_hits);
            if (res == 0) {
                proceeded_filters_hits++;
            }
            else if (res == 1) {
                proceeded_filters_hits = NsClasses.at(n)->getTcFiltersNum();
                m = sys->QosFiltersHits.size();
            }
        }
        if (proceeded_filters_hits < NsClasses.at(n)->getTcFiltersNum()) {
            // Workaround for impossible to read last filter on 3.14 and several newer kernels under x86
            if ((proceeded_filters_hits == (NsClasses.at(n)->getTcFiltersNum()-1)) && 
                    (NsClasses.at(n)->getTcFilterU32MaxId() == ifaces->getTcFilterU32MaxId(iface)) &&
                    (NsClasses.at(n)->getTcFilterU32MaxId() != ifaces->getTcFilterU32MinId(iface))) {
                if (ifaces->getWAMissLastU32Used(iface)) {
                    log->error(SectionName, 501);
                    return -1;
                }
                log->error(SectionName, 503);
                if (NsClasses.at(n)->addWAMissLastU32() == -1) return -1;
                ifaces->setWAMissLastU32Used(iface, true);
                NsClasses.at(n)->proceedQosFilterHits(NsClasses.at(n)->getTcFilterU32MaxId(), 1);
                continue;
            }
            log->error(SectionName, 501);
            log->setReqRecoverQos(true);
            return -1;
        }
    }

    return 0;
}

int NiceShaper::judge(struct timeval tv_curr, double round_duration)
{
    unsigned int ipt_ordered_counters_offset = 0;
    __u64 ipt_ordered_counters_sum = 0;

    if (SAOContainter) return 0;
   
    sys->cleanAccountingHelpers();

    if (sys->rtnlOpen() == -1) return -1;

    if (!IptRequiredToCheckActivity) {
        if (qosCheckFiltersHits() == -1) { sys->rtnlClose(); return -1; }
    }
    if (!IptRequiredToCheckTraffic) {
        if (qosCheckClassesBytes() == -1) { sys->rtnlClose(); return -1; }
    }

    sys->rtnlClose();

    ipt_ordered_counters_offset = 0;
    for (unsigned int n=0; n < NsClasses.size(); n++) {
        if (IptRequiredToCheckTraffic || IptRequiredToCheckActivity) {
            ipt_ordered_counters_sum = 0;
            for (unsigned int m=0; m < NsClasses.at(n)->getTcFiltersNum(); m++) {
                if (m) ipt_ordered_counters_offset++;
                ipt_ordered_counters_sum += IptOrderedCounters.at(n+ipt_ordered_counters_offset);
            }
        }

        if (NsClasses.at(n)->getIptRequiredToCheckTraffic()) {
            NsClasses.at(n)->proceedReceiptTraffic(ipt_ordered_counters_sum);
            NsClasses.at(n)->proceedReceiptIptCountersSum(ipt_ordered_counters_sum);
        }
        else if (NsClasses.at(n)->getIptRequiredToCheckActivity() && !NsClasses.at(n)->getQosInitialized()) {
            NsClasses.at(n)->proceedReceiptTraffic(ipt_ordered_counters_sum);
        }
        else if (NsClasses.at(n)->getIptRequiredToCheckActivity() && NsClasses.at(n)->getQosInitialized()) {
            NsClasses.at(n)->proceedReceiptIptCountersSum(ipt_ordered_counters_sum);
        }

        NsClasses.at(n)->proceedReceiptedTraffic(tv_curr, round_duration);
    }

    if (DnswDoNotShape) {
        ipt_ordered_counters_offset = 0;
        for (unsigned int n=0; n < NsClassesDnswStubs.size(); n++) {
            ipt_ordered_counters_sum = 0;
            for (unsigned int m=0; m < NsClassesDnswStubs.at(n)->getTcFiltersNum(); m++) {
                if (m) ipt_ordered_counters_offset++;
                ipt_ordered_counters_sum += IptOrderedCountersDnsw.at(n+ipt_ordered_counters_offset);
            }            

            if (NsClassesDnswStubs.at(n)->type() == DONOTSHAPE) {
                NsClassesDnswStubs.at(n)->proceedReceiptTraffic(ipt_ordered_counters_sum); 
            }
        }
    }

    if (DnswWrapper || DnswDoNotShape) {
        for (unsigned int n=0; n<NsClassesDnswStubs.size(); n++) {
            NsClassesDnswStubs.at(n)->proceedReceiptedTraffic(tv_curr, round_duration);
        }
    }

    if (judgeV12() == -1) return -1;

    if (sys->rtnlOpen() == -1) { return -1; }
    if (applyChanges() == -1) { sys->rtnlClose(); return -1; }
    sys->rtnlClose();

    return 0;
}

int NiceShaper::judgeV12()
{
    enum JudgePhase { JP_REDUCING_ACCEL, JP_REDUCING_PRECISE, JP_GAINING } phase;
    unsigned int loop_counter = 0;
    unsigned int section_traffic_prognosed = 0;
    unsigned int disparity = 0;
    unsigned int alignment = 0;
    unsigned int acceptable_margin = 1 * KBITS;
    unsigned int class_disparity = 0;
    unsigned int min_class_disparity = 0;
    unsigned int sum_inviolable_classes_traffic = 0;
    unsigned int sum_range_of_gaining = 0;
    double sum_grade_for_reducing = 0;
    std::vector <NsClass *> ns_classes_reducible;
    std::vector <NsClass *> ns_classes_enlargeable;
    NsClass *iterclass;   

    SectionTraffic = 0;
    Working = 0;

    // first profiling 
    for (unsigned int n=0; n<NsClasses.size(); n++)
    {
        iterclass=NsClasses.at(n);
        if (iterclass->getActive() && (iterclass->type() == STANDARD_CLASS))
        {
            Working++;
            SectionTraffic += iterclass->traffic();
            if (iterclass->nsLow() == iterclass->nsCeil()) {
                sum_inviolable_classes_traffic += iterclass->traffic();
                continue;
            }
            iterclass->computeGrade();
            if (iterclass->traffic() > iterclass->nsLow()) {
                ns_classes_reducible.push_back(iterclass);
                sum_grade_for_reducing += iterclass->gradeForReducing();
                if (iterclass->htbCeil() > iterclass->nsLow()) {
                    if (iterclass->htbCeil() > iterclass->traffic()) {
                        class_disparity = iterclass->htbCeil() - iterclass->traffic();
                        if (!min_class_disparity || (class_disparity < min_class_disparity)) min_class_disparity = class_disparity;
                    }
                    else min_class_disparity = 1;
                }
            }
            else {
                sum_inviolable_classes_traffic += iterclass->traffic();
            }

            if (iterclass->htbCeil() < iterclass->nsCeil()) {
                ns_classes_enlargeable.push_back(iterclass);
                sum_range_of_gaining += (iterclass->nsCeil()-iterclass->nsLow());
            }
        }
    }
    section_traffic_prognosed = SectionTraffic;
    acceptable_margin = (1 * KBITS) + (Working * 10 * BITS);

    if (!Working) return 0;
    if (SectionTraffic == SectionShape) return 0;

    if (SectionTraffic > SectionShape) { 
        if ((SectionTraffic - SectionShape) < min_class_disparity) phase = JP_REDUCING_ACCEL;
        else phase = JP_REDUCING_PRECISE;
    }
    else { phase = JP_GAINING; }

    do {
        if (loop_counter) {
            // Proceed after each but not first loop. 
            // This is only for reducing, gaining works only once.
            section_traffic_prognosed = sum_inviolable_classes_traffic;
            min_class_disparity = 0;
            if (ns_classes_reducible.empty()) return 0;
            for (unsigned int n=0; n<ns_classes_reducible.size(); n++) {
                iterclass=ns_classes_reducible.at(n);
                section_traffic_prognosed += iterclass->trafficPrognosed();
                if (iterclass->htbCeil() > iterclass->trafficPrognosed()) {
                    class_disparity = iterclass->htbCeil() - iterclass->trafficPrognosed();
                    if (!min_class_disparity || (class_disparity < min_class_disparity)) min_class_disparity = class_disparity;
                }
                else min_class_disparity = 1;
            }
        }

        if ((phase == JP_REDUCING_ACCEL) || (phase == JP_REDUCING_PRECISE)) {
            if ((section_traffic_prognosed >= SectionShape) && (section_traffic_prognosed <= (SectionShape+acceptable_margin))) return 0;
            if (section_traffic_prognosed < SectionShape) return 0; // It shouldn't happen
        }

        if (phase == JP_REDUCING_ACCEL) {
            if ((section_traffic_prognosed - SectionShape) >= min_class_disparity) {
                disparity = section_traffic_prognosed - SectionShape;
                phase = JP_REDUCING_PRECISE;
            }
            else {
                disparity = min_class_disparity;
            }
        }
        else if (phase == JP_REDUCING_PRECISE) {
            if ((section_traffic_prognosed - SectionShape) < min_class_disparity) {
                disparity = min_class_disparity;
                phase = JP_REDUCING_ACCEL;
            }
            else {
                disparity = section_traffic_prognosed - SectionShape;
            }
        }
        else if (phase == JP_GAINING) {
            disparity = SectionShape - section_traffic_prognosed;
        }

        if ((phase == JP_REDUCING_ACCEL) || (phase == JP_REDUCING_PRECISE)) {
            for (unsigned int n=0; n<ns_classes_reducible.size(); n++) {
                iterclass=ns_classes_reducible.at(n);
                alignment = disparity * (static_cast<double>(iterclass->gradeForReducing()) / static_cast<double>(sum_grade_for_reducing));
                if ((iterclass->htbCeil() - iterclass->nsLow()) > alignment) {
                    iterclass->decHtbCeil(alignment);
                }
                else {
                    iterclass->setHtbCeil(iterclass->nsLow());
                    sum_grade_for_reducing -= iterclass->gradeForReducing();
                    sum_inviolable_classes_traffic += iterclass->nsLow();
                    ns_classes_reducible.erase(ns_classes_reducible.begin()+n);
                    n--;
                }
            }
        }
        else if (phase == JP_GAINING) {
            for (unsigned int n=0; n<ns_classes_enlargeable.size(); n++) {
                iterclass=ns_classes_enlargeable.at(n);
                alignment = disparity * (static_cast<double>(iterclass->nsCeil()-iterclass->nsLow()) / static_cast<double>(sum_range_of_gaining));
                if ((iterclass->nsCeil() - iterclass->htbCeil()) > alignment) {
                    iterclass->incHtbCeil(alignment);
                }
                else iterclass->setHtbCeil(iterclass->nsCeil());
            }
            return 0;
        }

        loop_counter++;
    } while (loop_counter < 100);

    return 0; 
}
 

int NiceShaper::applyChanges()
{
    for (int i=NsClasses.size()-1; i>=0 ; i--) {
        if (NsClasses.at(i)->type() == STANDARD_CLASS) {
            if (NsClasses.at(i)->applyChanges(Working) == -1) return -1;
        }
    }

    return 0;
}

int NiceShaper::statusUnformatted(std::vector <std::string> &status_table)
{
    std::string buf, sum;
    unsigned int dnsw_count;

    status_table.clear();

    dnsw_count = 0;

    status_table.push_back(SectionName + " ceil last-ceil last-traffic");

    if (config->getStatusShowSum() != SS_FALSE)
    {
        sum = "sum(classes:" + aux::int_to_str(Working) + ") " + aux::int_to_str(SectionShape) + " " + aux::int_to_str(SectionShape) + " " + aux::int_to_str(SectionTraffic);
    }   

    if (config->getStatusShowSum() == SS_TOP) 
    {
        status_table.push_back(sum);
    }

    if (config->getStatusShowClasses() != SC_FALSE )
    {
        for (unsigned int n=0; n<=NsClasses.size(); n++ ) {
            if (DnswWrapper || DnswDoNotShape) {
                while ((dnsw_count < NsClassesDnswStubs.size()) && (NsClassesDnswStubs.at(dnsw_count)->getDnswStubBefore() == n)) {
                    buf = NsClassesDnswStubs.at(dnsw_count)->status();
                    if (buf.size()) status_table.push_back(buf);
                    dnsw_count++;
                }
            }
            if (n<NsClasses.size()) {
                buf = NsClasses.at(n)->status();
                if (buf.size()) status_table.push_back(buf);
            }
        }
    }

    if (config->getStatusShowSum() == SS_BOTTOM)
    {
        status_table.push_back(sum);
    }

    return 0;
}

std::vector <std::string> NiceShaper::dumpQuotaCounters ()
{
    std::vector <std::string> counters_table;
    std::string counters;

    for (unsigned int n=0; n<NsClasses.size(); n++) {
        counters = NsClasses.at(n)->dumpQuotaCounters();
        if (!counters.empty()) counters_table.push_back(counters);
    }

    return counters_table;
}

int NiceShaper::setQuotaCounters (std::vector <std::string> &counters_table)
{
    unsigned int counter_day, counter_week, counter_month;
    std::vector <std::string>::iterator fpvi, fpvi_end;
    std::string class_name = "";

    if (counters_table.empty()) return 0;
    
    fpvi = counters_table.begin();
    fpvi_end = counters_table.end();
    while (fpvi < fpvi_end) {
        class_name = aux::awk(*fpvi, 1); 
        for (unsigned int n=0; n<NsClasses.size(); n++) {    
            if (class_name == NsClasses.at(n)->name()) { 
                counter_day = aux::str_to_uint(aux::awk (*fpvi, 2));
                counter_week = aux::str_to_uint(aux::awk (*fpvi, 3));
                counter_month = aux::str_to_uint(aux::awk (*fpvi, 4));
                NsClasses.at(n)->setQuotaCounters (counter_day, counter_week, counter_month); 
                break; 
            }
        }
        fpvi++;
    }

    return 0;
}



