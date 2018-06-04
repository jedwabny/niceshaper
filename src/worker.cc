/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "worker.h"

#include <cstdlib>
#include <cerrno>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "config.h"
#include "aux.h"
#include "logger.h"
#include "ifaces.h"
#include "sys.h"
#include "niceshaper.h"

Worker::Worker(std::string section_name, unsigned int section_id, unsigned int waitingroom_id, bool sao_container)
{
    SectionName = section_name;
    SectionId = section_id;
    WaitingRoomId = waitingroom_id;
    SAOContainter = sao_container; 
    QuotaFile = "";
    ReloadsCounter = 0;        
    CycleReportMinMsec = 0;
    CycleReportMaxMsec = 0;
    CycleReportSumMsec = 0;
    CycleReportCounter = 0;
    CycleReportInitialized = false;
    StatusTableUnformatted.clear();
    NS = NULL;
}

Worker::~Worker()
{
    if (QuotaFile.size()) quotaCountersSave();    

    if (NS != NULL) delete NS;

    if (!SAOContainter) pthread_mutex_destroy(&StatusTableUnformattedLock);
}

void Worker::statusTableUnformattedLockUnlockWithTrylock()
{
    int result;

    result = pthread_mutex_trylock(&StatusTableUnformattedLock);

    if ((result == 0) || (result == EBUSY)) pthread_mutex_unlock(&StatusTableUnformattedLock);
}

int Worker::init(std::vector <std::string> &fpv_conffile, std::vector <std::string> &fpv_classfile)
{
    struct stat vardir_stat;
    struct timeval tv_curr;

    log->info(3, SectionName);

    if (!SAOContainter) {
        QuotaFile = vardir + "/" + SectionName + ".quota";
        if ((stat(vardir.c_str(), &vardir_stat) == -1) || (!S_ISDIR(vardir_stat.st_mode))) QuotaFile = "";
    }

    NS = new NiceShaper(SectionName, SectionId, WaitingRoomId, SAOContainter);

    if (NS->init(fpv_conffile, fpv_classfile) == -1) {
        log->error(SectionName, 30);
        return -1;
    }
 
    if (SAOContainter) return 0;

    if (QuotaFile.size()) {
        quotaCountersLoad();
        rename (QuotaFile.c_str(), (QuotaFile+".bak").c_str());
        quotaCountersSave();
    }

    gettimeofday (&tv_curr, NULL);

    CycleReportPrevSec = tv_curr.tv_sec;
    QuotaSavePrevSec = tv_curr.tv_sec;

    if (pthread_mutex_init(&StatusTableUnformattedLock, NULL) != 0) {
        log->error(403);
        return -1;
    }

    return 0;
}

int Worker::recoverQos()
{
    if (NS->recoverQos() == -1) {
        log->error(SectionName, 30);
        return -1;
    }

    return 0;   
}

unsigned int Worker::getSectionReload()
{
    return NS->getReload();
}

EnumFlowDirection Worker::getFlowDirection() 
{ 
    return NS->getFlowDirection();
}

void Worker::setIptRequired(bool required)
{
    NS->setIptRequired(required);
}

void Worker::setIptRequiredToCheckActivity(bool required)
{
    NS->setIptRequiredToCheckActivity(required);
}

bool Worker::getIptRequired() 
{ 
    return NS->getIptRequired(); 
}

bool Worker::getIptRequiredToCheck() 
{ 
    return NS->getIptRequiredToCheck();
}

void Worker::getIptRequirementsIfRequired(bool &dwload_ipt_required, bool &dwload_ipt_required_to_check, bool &upload_ipt_required, bool &upload_ipt_required_to_check)
{
    if (NS->getIptRequired()) {
        if (NS->getFlowDirection() == DWLOAD) dwload_ipt_required = true;
        else if (NS->getFlowDirection() == UPLOAD) upload_ipt_required = true;
    }

    if (NS->getIptRequiredToCheck()) {
        if (NS->getFlowDirection() == DWLOAD) dwload_ipt_required_to_check = true;
        else if (NS->getFlowDirection() == UPLOAD) upload_ipt_required_to_check = true;
    }
}

int Worker::proceedRoundReportValues(struct timeval &tv_curr, struct timeval &tv_prev)
{
    unsigned int cycle_report_msec = 0;

    cycle_report_msec = (tv_curr.tv_sec-tv_prev.tv_sec)*1000+(tv_curr.tv_usec-tv_prev.tv_usec)/1000;

    if (!CycleReportInitialized) {
        CycleReportMinMsec = cycle_report_msec;
        CycleReportMaxMsec = cycle_report_msec;
        CycleReportSumMsec = 0;
        CycleReportCounter = 0;
        CycleReportInitialized = true;
    }

    if (CycleReportMinMsec > cycle_report_msec) CycleReportMinMsec = cycle_report_msec;
    if (CycleReportMaxMsec < cycle_report_msec) CycleReportMaxMsec = cycle_report_msec;

    CycleReportSumMsec += cycle_report_msec;
    CycleReportCounter++;

    return 0;
}

int Worker::receiptIptTraffic (std::vector <__u64> &ipt_ordered_counters, std::vector <__u64> &ipt_ordered_counters_dnsw)
{
    if (NS->receiptIptTraffic (ipt_ordered_counters, ipt_ordered_counters_dnsw) == -1) return -1;

    return 0;
}
 
int Worker::reload(struct timeval tv_curr, double round_duration)
{
    unsigned int cycle_report_rewrite_sec = 3600;
    unsigned int quota_counters_rewrite_sec = 300;
    std::string buf = "";

    pthread_mutex_lock(&StatusTableUnformattedLock);

    if (NS->judge(tv_curr, round_duration) == -1) {
        pthread_mutex_unlock(&StatusTableUnformattedLock);
        return -1;
    }

    StatusTableUnformatted.clear();

    pthread_mutex_unlock(&StatusTableUnformattedLock);

    // Dump round duration report
    if ((tv_curr.tv_sec-CycleReportPrevSec) >= cycle_report_rewrite_sec) {
        buf = "min: " + aux::int_to_str(CycleReportMinMsec/1000) + "." + aux::int_to_str((CycleReportMinMsec % 1000), 3) + "s " +
            "avg: " + aux::int_to_str(CycleReportSumMsec/CycleReportCounter/1000) + "." + aux::int_to_str(((CycleReportSumMsec/CycleReportCounter) % 1000) ,3) + "s "
            "max: " + aux::int_to_str(CycleReportMaxMsec/1000) + "." + aux::int_to_str((CycleReportMaxMsec % 1000), 3) + "s";
        log->info(SectionName, 9, buf);
        CycleReportPrevSec = tv_curr.tv_sec;
        CycleReportInitialized = false;
    }

    // Save quota counters
    if ((tv_curr.tv_sec-QuotaSavePrevSec) >= quota_counters_rewrite_sec ) {
        quotaCountersSave(); 
        QuotaSavePrevSec = tv_curr.tv_sec;
    }

    return 0;
}

int Worker::statusFormattedAppend(EnumUnits status_unit, std::vector <std::string> &status_table)
{
    const int max_rate_size = aux::int_to_str(MAX_RATE).size() + 4;
    std::string status_row;
    std::string buf;

    pthread_mutex_lock(&StatusTableUnformattedLock);

    if (StatusTableUnformatted.empty()) {
        NS->statusUnformatted(StatusTableUnformatted);
    }

    pthread_mutex_unlock(&StatusTableUnformattedLock);

    for (unsigned int n=0; n<StatusTableUnformatted.size(); n++) {
        status_row = StatusTableUnformatted.at(n);
        // Name column
        buf = statusUndent(aux::awk(status_row, 1), MAX_CLASS_NAME_SIZE) + "  ";
        if (n)
        {
            // Ceil column
            if ( aux::awk(status_row, 2 ) != "-" ) {
                buf += statusIndent((aux::int_to_str(aux::unit_convert(aux::awk(status_row, 2), status_unit)) + aux::unit_to_str(status_unit, 0)), max_rate_size) + " - ";
            }
            else {
                buf += std::string(max_rate_size , ' ') + "   ";
            }

            // Last-Ceil column
            if ( aux::awk( status_row, 3 ) != "-" ) {
                buf += statusIndent((aux::int_to_str(aux::unit_convert(aux::awk(status_row, 3), status_unit)) + aux::unit_to_str(status_unit, 0)), max_rate_size ) + " ";
            }
            else {
                buf += std::string(max_rate_size, ' ') + " ";
            }

            // Last-Utilize column
            if ( aux::awk(status_row, 4) != "-" ) {
                buf += "( " + statusIndent((aux::int_to_str(aux::unit_convert(aux::awk(status_row, 4), status_unit)) + aux::unit_to_str(status_unit, 0)), max_rate_size) + " )";
            }
            else {
                buf += "( " + std::string(max_rate_size, ' ') + " )";
            }
        }
        else
        {
            buf += statusIndent(aux::awk(status_row, 2), max_rate_size) + " - ";
            buf += statusIndent(aux::awk(status_row, 3), max_rate_size);
            buf += " ( " + statusIndent(aux::awk(status_row, 4), max_rate_size) + " )";
        }

        status_table.push_back(buf);
    }

    return 0;
}

std::string Worker::statusUndent(std::string arg, unsigned int count)
{
    std::string res = "";

    res.assign(arg, 0 , count);
    if (count > res.size()) {
        res.append(count-res.size(), ' ');
    }

    return res;
}

std::string Worker::statusIndent(std::string arg, unsigned int count)
{
    std::string res = "";

    if (count > arg.size()) {
        res.append(count-arg.size(), ' ');
    }

    res.append(arg, 0 , count);

    return res;
}

int Worker::quotaCountersSave()
{
    std::vector <std::string> quotas_table;
    std::vector <std::string>::iterator qti;
    std::ofstream ofd;

    quotas_table = NS->dumpQuotaCounters();
    
    if (quotas_table.size()) {        
        ofd.open(QuotaFile.c_str());
        if (ofd.is_open()) {
            qti = quotas_table.begin();
            while (qti < quotas_table.end()) {
                ofd << *qti + '\n';;
                qti++;
            }
            ofd.close();
        }
        else {
            log->error(SectionName, 27, QuotaFile);
        }
    }

    return 0;
}

int Worker::quotaCountersLoad()
{
    std::vector <std::string> quota_counters_table;
    std::ifstream ifd;
    std::string buf;

    ifd.open (QuotaFile.c_str());
    if (ifd.is_open()) {
        while (getline(ifd ,buf)) {
            quota_counters_table.push_back (buf);
        }            
        ifd.close();
        if (quota_counters_table.size()) NS->setQuotaCounters(quota_counters_table);
    }

    return 0;
}

WorkerReloadDemand::WorkerReloadDemand(unsigned int worker_vid, struct timeval tv_reload_demand)
{
    WorkerVID = worker_vid;
    TVReloadDemand = tv_reload_demand;
}

WorkerReloadDemand::~WorkerReloadDemand()
{
    //
}


