/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "supervisor.h"

#include <cstdlib>
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "main.h"
#include "aux.h"
#include "config.h"
#include "ifaces.h"
#include "iptables.h"
#include "logger.h"
#include "talk.h"
#include "tests.h"
#include "worker.h"

Supervisor::Supervisor()
{
    ControllerHandlerSocket = 0;
    ControllerHandlersCreated = false;
    ControllerHandlerGoHome = 0;

    StatusWriterCreated = false;
    StatusWriterGoHome = 0;

    StatusFileOutOfDate = false;

    Initialized = false;

    SAOContainterRequired = false;
}

Supervisor::~Supervisor()
{
    unsigned int ret;

    if (!Initialized) return;

    pthread_mutex_lock(&ThreadsExitRequestLock);

    if (ControllerHandlersCreated) ControllerHandlerGoHome = MAX_CONTROLLER_HANDLERS;
    if (StatusWriterCreated) StatusWriterGoHome = 1;

    pthread_mutex_unlock(&ThreadsExitRequestLock);

    for (unsigned int n=1; n<Workers.size(); n++) {
        Workers.at(n)->statusTableUnformattedLockUnlockWithTrylock();
    }

    if (ControllerHandlersCreated) {
        do {
            usleep (100000);
            pthread_mutex_lock(&ThreadsExitRequestLock);
            ret = ControllerHandlerGoHome;
            pthread_mutex_unlock(&ThreadsExitRequestLock);
        } while (ret != 0);
    }

    if (ControllerHandlerSocket) close (ControllerHandlerSocket);

    if (StatusWriterCreated) {
        do {
            usleep (100000);
            pthread_mutex_lock(&ThreadsExitRequestLock);
            ret = StatusWriterGoHome;
            pthread_mutex_unlock(&ThreadsExitRequestLock);
        } while (ret != 0);
    }

    for (unsigned int n=0; n<Workers.size(); n++) {
        delete Workers.at(n);
    }

    Workers.clear();

    delete ipt;
    delete ifaces;

    if (test->fileExists(pidfile)) unlink(pidfile.c_str());
    if (test->fileExists(svinfofile)) unlink(svinfofile.c_str());

    pthread_mutex_destroy(&ThreadsExitRequestLock);
    pthread_mutex_destroy(&ControllerHandlerLock);
    pthread_mutex_destroy(&StatusFileOutOfDateLock);
}

int Supervisor::init()
{
    struct stat vardir_stat;
    struct timeval tv_supervisor_socket;
    struct sockaddr_in address; 
    int yes = 1;

    // Empty running sections list
    if (config->RunningSections.empty()) { log->error(15); return -1; }
    if (config->LocalSubnets.empty()) { log->error(808); return -1; }

    // Check for vardir
    if ((stat(vardir.c_str(), &vardir_stat) == -1) || (!S_ISDIR(vardir_stat.st_mode))) {
        log->warning(14, vardir);
        ipt->setFallback(true);
    }
    
    // Check for executables
    if (test->whichExecutable("iptables-save").empty()) { log->warning(16); ipt->setFallback(true); }
    if (test->whichExecutable("iptables-restore").empty()) { log->warning(17); ipt->setFallback(true); }
    if (test->whichExecutable("iptables").empty()) { log->error(703); return -1; }
    if (test->whichExecutable("tc").empty()) { log->error(704); return -1; }

    // Create socket for status demands
    tv_supervisor_socket.tv_sec = 30;
    ControllerHandlerSocket = socket (AF_INET, SOCK_STREAM, 0);
    setsockopt (ControllerHandlerSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    setsockopt (ControllerHandlerSocket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv_supervisor_socket, sizeof(struct timeval));
    bzero((char *) &address, sizeof(address));
    address.sin_port = htons(config->getListenerPort());
    address.sin_addr.s_addr = inet_addr (config->getListenerIp().c_str());
    address.sin_family = AF_INET; 
    if (bind (ControllerHandlerSocket, (struct sockaddr *) &address, sizeof(address)) == -1 ) {
        log->error (51, (config->getListenerIp() + ":" + aux::int_to_str(config->getListenerPort())));
        return -1;
    }
    listen (ControllerHandlerSocket, 10);
 
    Initialized = true;

    return 0;
}

int Supervisor::entry (std::vector <std::string> &fpv_conffile, std::vector <std::string> &fpv_classfile)
{
    bool dwload_ipt_required = false;
    bool dwload_ipt_required_to_check = false;
    bool upload_ipt_required = false;
    bool upload_ipt_required_to_check = false;
    std::string buf;
    std::string section_name;
    bool sao_container;
    std::ofstream ofd;
    FPVConfFile = fpv_conffile;
    FPVClassFile = fpv_classfile;

    if (pthread_mutex_init(&ThreadsExitRequestLock, NULL) != 0) {
        log->error(406);
        return -1;
    }

    // Create pid file
    ofd.open(pidfile.c_str());
    if (!ofd.is_open()) { log->error(48, pidfile); return -1; }
    ofd << aux::int_to_str(getpid()) + '\n';
    ofd.close();

    // Publish listening address, and port, and password for loopback client connections
    ofd.open(svinfofile.c_str());
    if (!ofd.is_open()) { log->error(48, svinfofile); return -1; }
    ofd << config->getListenerIp() << ":" << config->getListenerPort() << ":" << config->getListenerPassword() << '\n';
    ofd.close();

    if (prepareEnvironment(fpv_conffile, fpv_classfile) == -1) return -1; 

    for (unsigned int n=0; n<=config->RunningSections.size(); n++) {
        if (n) {
            section_name = config->RunningSections.at(n-1);
            sao_container = false;
        }
        else {
            // Workers.at(0) for shared and orphaned classes processing (class-wrapper and class-do-not-shape)
            section_name = "shared-and-orphaned";
            sao_container = true;
        }

        Workers.push_back(new Worker(section_name, FIRST_SECTION_ID+n, FIRST_WAITINGROOM_ID+n, sao_container));
        if (!sao_container || (sao_container && SAOContainterRequired)) {
            if (Workers.at(n)->init(fpv_conffile, fpv_classfile) == -1) { log->error(section_name, 30); return -1; }
            if (n) Workers.at(n)->getIptRequirementsIfRequired(dwload_ipt_required, dwload_ipt_required_to_check, upload_ipt_required, upload_ipt_required_to_check);
        }
    }

    ipt->setRequirementsIfRequired(dwload_ipt_required, dwload_ipt_required_to_check, upload_ipt_required, upload_ipt_required_to_check);

    // Prepare and initialize iptables rules
    if (ipt->prepare(fpv_classfile, Workers) == -1) return -1;
    if (ipt->init() == -1) return -1;

    // Set permissions on status file 
    if (config->getStatusFilePath().size())
    {
        if (access (config->getStatusFilePath().c_str(), W_OK)) creat (config->getStatusFilePath().c_str(), O_WRONLY);
        buf = "chown " + config->getStatusFileOwner() + ":" + config->getStatusFileGroup() + " " + config->getStatusFilePath()
            + " && chmod " + config->getStatusFileMode() + " " + config->getStatusFilePath() + " &";
        system (buf.c_str());
    }

    return 0;
}

int Supervisor::loop ()
{
    struct timeval tv_sleep_duration, tv_round_duration, tv_reload_demand;
    struct timeval tv_round_report_curr;
    double round_duration;
    bool htb_fallback_fully_initialized = false;
    bool sections_all_reloaded = false;
    std::vector <__u64> ipt_ordered_counters;
    std::vector <__u64> ipt_ordered_counters_dnsw;
    Worker *next_worker = NULL;
    unsigned int next_worker_vid;
    struct timeval next_worker_tv;
    pthread_t controller_handler_tid[MAX_CONTROLLER_HANDLERS];
    pthread_t status_writer_tid[1];

    reloadsVectorInit();

    if (pthread_mutex_init(&ControllerHandlerLock, NULL) != 0) {
        log->error(403);
        return -1;
    }

    if (pthread_mutex_init(&StatusFileOutOfDateLock, NULL) != 0) {
        log->error(403);
        return -1;
    }

    for (unsigned int n=0; n<MAX_CONTROLLER_HANDLERS; n++) {
        if (pthread_create(&(controller_handler_tid[n]), NULL, &Supervisor::controllerHandlerThreadEntry, this) < 0) {
            log->error(402);
            return -1;
        }
        ControllerHandlersCreated = true;
    }

    while (true)
    {
        next_worker_vid = ReloadsVector.at(0)->WorkerVID;
        next_worker_tv = ReloadsVector.at(0)->TVReloadDemand;
        next_worker = Workers.at(next_worker_vid);

        delete ReloadsVector.at(0);
        ReloadsVector.erase(ReloadsVector.begin());

        gettimeofday (&next_worker->TVSleepCurr, NULL);

        while (timercmp(&next_worker->TVSleepCurr, &next_worker_tv, <))
        {
            timersub(&next_worker_tv, &next_worker->TVSleepCurr, &tv_sleep_duration); 
 
            if (tv_sleep_duration.tv_sec) {
                if (sleep(static_cast<unsigned int>(tv_sleep_duration.tv_sec)) != 0) {
                    gettimeofday (&next_worker->TVSleepCurr, NULL);
                    continue;
                }
            }

            if (usleep(static_cast<unsigned int>(tv_sleep_duration.tv_usec)) != 0) 
            {
                gettimeofday (&next_worker->TVSleepCurr, NULL);
                continue;    
            }

            gettimeofday (&next_worker->TVSleepCurr, NULL);
        }

        gettimeofday(&next_worker->TVSleepPrev, NULL);

        if (next_worker->getIptRequiredToCheck()) {
            ipt_ordered_counters.clear();
            ipt_ordered_counters_dnsw.clear();
            if (ipt->checkTraffic(next_worker->getFlowDirection(), next_worker_vid, ipt_ordered_counters, ipt_ordered_counters_dnsw) == -1) {
                if (sections_all_reloaded && log->getReqRecoverIpt()) {
                    if (recoverIpt() == -1) return -1;
                    reloadsVectorInit();
                    sections_all_reloaded = false;
                    continue;
                }
                else {
                    return -1;
                }
            }

            if (next_worker->receiptIptTraffic(ipt_ordered_counters, ipt_ordered_counters_dnsw) == -1) return -1;
        }

        gettimeofday(&next_worker->TVRoundCurr, NULL);
        timersub (&next_worker->TVRoundCurr, &next_worker->TVRoundPrev, &tv_round_duration);
        round_duration = static_cast<double>(tv_round_duration.tv_sec) + static_cast<double>(tv_round_duration.tv_usec)/1000000;
        next_worker->TVRoundPrev = next_worker->TVRoundCurr;

        if (next_worker->reload(next_worker->TVRoundCurr, round_duration) == -1) {
            if (!sections_all_reloaded && log->getReqRecoverMissU32Perf()) {
                if (recoverMissU32Perf() == -1) return -1;
                reloadsVectorInit();
                sections_all_reloaded = false;
                continue;
            }
            else if (sections_all_reloaded && log->getReqRecoverQos()) {
                if (recoverQos() == -1) return -1;
                reloadsVectorInit();
                htb_fallback_fully_initialized = false;
                sections_all_reloaded = false;
                continue;
            }
            else return -1;
        }

        pthread_mutex_lock(&StatusFileOutOfDateLock);
        StatusFileOutOfDate = true;
        pthread_mutex_unlock(&StatusFileOutOfDateLock);

        next_worker->incReloadsCounter();
 
        tv_reload_demand = next_worker->TVSleepPrev;
        tv_reload_demand.tv_sec +=  next_worker->getSectionReload() / 1000000;
        tv_reload_demand.tv_usec +=  next_worker->getSectionReload() % 1000000;
        reloadsVectorInsert(next_worker_vid, tv_reload_demand);

        // Initialize htb fallback with proper rate if all sections are reloaded at least once
        if (!sections_all_reloaded) {
            sections_all_reloaded = true;
            for (unsigned int n=1; n<Workers.size(); n++) {
                if (!Workers.at(n)->getReloadsCounter()) sections_all_reloaded = false;
            }
        }

        if (sections_all_reloaded) {
            if (!htb_fallback_fully_initialized) {
                if (ifaces->endUpHtbFallbackOnControlled() == -1) return -1;
                htb_fallback_fully_initialized = true;
            }
        }

        // Initialize status writer thread
        if (!StatusWriterCreated && config->getStatusFilePath().size()) {
            if (pthread_create(&(status_writer_tid[0]), NULL, &Supervisor::statusWriterThreadEntry, this) < 0) {
                log->error(405);
                return -1;
            }

            StatusWriterCreated = true;
        }
 
        gettimeofday(&tv_round_report_curr, NULL);
        next_worker->proceedRoundReportValues(tv_round_report_curr, next_worker->TVSleepPrev);
    }
}

int Supervisor::reloadsVectorInit()
{
    struct timeval tv_reload_cur, tv_reload_demand;

    gettimeofday(&tv_reload_cur, NULL);

    for (unsigned int n=0; n<ReloadsVector.size(); n++) {
        delete ReloadsVector.at(n);
    }

    ReloadsVector.clear();

    for (unsigned int n=1; n<Workers.size(); n++) {
        Workers.at(n)->TVRoundPrev = tv_reload_cur;
        Workers.at(n)->TVSleepPrev = tv_reload_cur;
        tv_reload_demand = tv_reload_cur;
        tv_reload_demand.tv_sec +=  Workers.at(n)->getSectionReload() / 1000000;
        tv_reload_demand.tv_usec +=  Workers.at(n)->getSectionReload() % 1000000;
        reloadsVectorInsert(n, tv_reload_demand);
    }

    return 0;
}

int Supervisor::reloadsVectorInsert(unsigned int worker_vid, struct timeval tv_reload_demand)
{
    WorkerReloadDemand *worker_reload_demand = NULL;

    worker_reload_demand = new WorkerReloadDemand(worker_vid, tv_reload_demand);

    for (unsigned int n=0; n<ReloadsVector.size(); n++)
    {
        if (timercmp(&tv_reload_demand, &ReloadsVector.at(n)->TVReloadDemand, <)) {
            ReloadsVector.insert(ReloadsVector.begin()+n, worker_reload_demand);
            return 0;
        }
    }

    ReloadsVector.push_back(worker_reload_demand);

    return 0;
}

int Supervisor::recoverIpt() 
{
    bool recover_success = false;

    do {
        log->info(11);
        sleep(config->getReqRecoverWait());
        log->info(12);
        log->setReqRecoverIpt(false); 
        recover_success = true;
        if (ipt->init() == -1) recover_success = false;
    } while (!recover_success);
    
    log->info(13);

    pthread_mutex_lock(&StatusFileOutOfDateLock);
    StatusFileOutOfDate = true;
    pthread_mutex_unlock(&StatusFileOutOfDateLock);

    return 0;       
}

int Supervisor::recoverQos()
{
    bool recover_success = false;

    do {
        log->info(11);
        sleep(config->getReqRecoverWait());
        log->info(12);
        log->setReqRecoverQos(false);
        recover_success = false;
        ifaces->discover();
        if (ifaces->initHtbOnControlled() == -1) continue;
        recover_success = true;
        for (unsigned int n=0; n<Workers.size(); n++) {
            if ((n==0) && !SAOContainterRequired) continue;
            if (Workers.at(n)->recoverQos() == -1) { 
                recover_success = false;
                n = Workers.size();
                continue;
            }
            Workers.at(n)->resetReloadsCounter();
        }
    } while (!recover_success);
 
    log->info(13);

    pthread_mutex_lock(&StatusFileOutOfDateLock);
    StatusFileOutOfDate = true;
    pthread_mutex_unlock(&StatusFileOutOfDateLock);

    return 0;
}

int Supervisor::recoverMissU32Perf()
{
    bool dwload_ipt_required = false;
    bool dwload_ipt_required_to_check = false;
    bool upload_ipt_required = false;
    bool upload_ipt_required_to_check = false;
   
    log->info(12);
    log->setReqRecoverMissU32Perf(false);

    if (ipt->clean() == -1) return -1;

    for (unsigned int n=1; n<Workers.size(); n++) {
        Workers.at(n)->setIptRequired(true);
        Workers.at(n)->setIptRequiredToCheckActivity(true);
        Workers.at(n)->getIptRequirementsIfRequired(dwload_ipt_required, dwload_ipt_required_to_check, upload_ipt_required, upload_ipt_required_to_check);
    }

    ipt->setRequirementsIfRequired(dwload_ipt_required, dwload_ipt_required_to_check, upload_ipt_required, upload_ipt_required_to_check);

    if (ipt->prepare(FPVClassFile, Workers) == -1) return -1;
    if (ipt->init() == -1) return -1;

    log->info(13);

    pthread_mutex_lock(&StatusFileOutOfDateLock);
    StatusFileOutOfDate = true;
    pthread_mutex_unlock(&StatusFileOutOfDateLock);

    return 0;
}

void *Supervisor::controllerHandlerThreadEntry(void *arg)
{
    Supervisor *supervisor_ptr = reinterpret_cast<Supervisor *>(arg);
    supervisor_ptr->controllerHandler();

    return 0;
}

void *Supervisor::controllerHandler()
{
    std::vector <std::string> result_table;
    std::string request = "";
    std::string request_cmd = "";
    std::string request_local_password = "";
    std::string request_show_running = "";
    std::string buf;
    EnumUnits request_status_unit = config->getStatusUnit();
    class Talk *talk;
    int connection_socket;
    int fd_max;
    int select_result;
    fd_set rfds;
    struct timeval tv_select_timeout;
    
    talk = new Talk;

    while (true)
    {
        pthread_mutex_lock(&ControllerHandlerLock);
        select_result = 0; 
        do {
            pthread_mutex_lock(&ThreadsExitRequestLock);
            if (ControllerHandlerGoHome > 0)
            {
                ControllerHandlerGoHome--;
                delete talk;
                pthread_mutex_unlock(&ControllerHandlerLock);
                pthread_mutex_unlock(&ThreadsExitRequestLock);
                pthread_exit(NULL);
            }
            pthread_mutex_unlock(&ThreadsExitRequestLock);
            FD_ZERO (&rfds);
            FD_SET (ControllerHandlerSocket, &rfds);
            fd_max = ControllerHandlerSocket + 1;
            tv_select_timeout.tv_sec = 0; // ControllerHandlerGoHome checking interval
            tv_select_timeout.tv_usec = 100000;
            select_result = select(fd_max, &rfds, NULL, NULL, &tv_select_timeout);
        } while (select_result == 0);

        if (select_result == -1)
        {
            log->error("supervisor", 301);
            usleep (5000000);
            pthread_mutex_unlock(&ControllerHandlerLock);
            continue;
        }

        connection_socket = accept (ControllerHandlerSocket, NULL, NULL);

        if (connection_socket < 0) {
            log->error("supervisor", 301);
            usleep (5000000);
            pthread_mutex_unlock(&ControllerHandlerLock);
            continue;
        }
        pthread_mutex_unlock(&ControllerHandlerLock);

        if ((talk->recvText (connection_socket, request) == -1) || request.empty()) { 
            usleep (5000000);
            shutdown (connection_socket, SHUT_RDWR); 
            close (connection_socket); 
            continue; 
        }

        request_cmd = aux::awk(request, 1);

        if ((request_cmd == "status") || (request_cmd == "stats") || (request_cmd == "show")) {
            if (request_cmd == "stats") log->warning(18);

            request_local_password = "";
            request_status_unit = config->getStatusUnit();
            request_show_running = "";

            // Proceed request params
            for (unsigned int n=2; aux::awk(request, n).size(); n++) {
                if (aux::awk(request, n) == "--password") {
                    request_local_password = aux::awk(request, ++n);
                }
                else if (aux::awk(request, n) == "--unit") {
                    request_status_unit = aux::get_unit (aux::awk(request, ++n));
                }
                else if (aux::awk(request, n) == "--running") {
                    request_show_running = aux::awk(request, ++n);
                }
            }

            result_table.clear();

            if (request_local_password != config->getListenerPassword()) {
                result_table.push_back(log->getErrorMessage(57));
                usleep (1000000);
            }
            else {
                if ((request_cmd == "status") || (request_cmd == "stats")) {
                    for (unsigned int n=1; n<Workers.size(); n++) {
                        Workers.at(n)->statusFormattedAppend(request_status_unit, result_table);
                        result_table.push_back("");
                    }
                }
                else if (request_cmd == "show") {
                    if (request_show_running == "config") {
                        for (unsigned int n=0; n<FPVConfFile.size(); n++) {
                            buf = FPVConfFile.at(n);
                            if ((buf.size()) && (aux::awk(buf, 2).empty()) && (buf.at(0) == '<') && (buf.at(buf.size()-1) == '>')) result_table.push_back("\n" + buf);
                            else result_table.push_back("    " + buf);
                        }                       
                    }
                    else if (request_show_running == "classes") {
                        for (unsigned int n=0; n<FPVClassFile.size(); n++) {
                            buf = FPVClassFile.at(n);
                            if (aux::is_in_vector(config->ProperClassesTypes, aux::awk(buf, 1))) result_table.push_back("\n" + buf);
                            else result_table.push_back("    " + buf);
                        }
                    }
                    else {
                        result_table.push_back(log->getErrorMessage(810));
                    }
                    result_table.push_back("");
                }
            }

            talk->sendTextVector(connection_socket, result_table);
        }

        shutdown (connection_socket, SHUT_RDWR);
        close (connection_socket);
    }

    pthread_exit(NULL);
}

void *Supervisor::statusWriterThreadEntry(void *arg)
{
    Supervisor *supervisor_ptr = reinterpret_cast<Supervisor *>(arg);
    supervisor_ptr->statusWriter();

    return 0;
}

void *Supervisor::statusWriter()
{
    std::vector <std::string> status_table;
    std::string buf;
    struct timeval tv_status_curr, tv_status_prev;
    int fd;
    bool out_of_date, out_of_time;

    while (true)
    {
        out_of_date = false;
        out_of_time = false;

        gettimeofday(&tv_status_prev, NULL);

        do {
            pthread_mutex_lock(&ThreadsExitRequestLock);
            if (StatusWriterGoHome > 0)
            {
                StatusWriterGoHome--;
                pthread_mutex_unlock(&ThreadsExitRequestLock);
                pthread_exit(NULL);
            }
            pthread_mutex_unlock(&ThreadsExitRequestLock);
            usleep(100000);
            if (!out_of_date) {
                pthread_mutex_lock(&StatusFileOutOfDateLock);
                out_of_date = StatusFileOutOfDate;
                pthread_mutex_unlock(&StatusFileOutOfDateLock);
            }
            if (!out_of_time) {
                gettimeofday (&tv_status_curr, NULL);
                if ((tv_status_curr.tv_sec-tv_status_prev.tv_sec) >= config->getStatusFileRewrite()) {
                    out_of_time = true;
                }
            }
        } while (!out_of_date || !out_of_time);

        status_table.clear();
        fd = open(config->getStatusFilePath().c_str(), O_RDWR | O_TRUNC);

        for (unsigned int n=1; n<Workers.size(); n++) 
        {
            Workers.at(n)->statusFormattedAppend(config->getStatusUnit(), status_table);
            status_table.push_back(std::string(""));
        }

        for (unsigned int n=0; n<status_table.size(); n++)
        {
            buf = status_table.at(n);
            write(fd, (buf + "\n").c_str(), buf.size()+1);
        }

        buf = "Powered by NiceShaper\n";
        write(fd, buf.c_str(), buf.size());
        buf = "http://niceshaper.jedwabny.net\n";
        write(fd, buf.c_str(), buf.size());
        close(fd);
 
        pthread_mutex_lock(&StatusFileOutOfDateLock);
        StatusFileOutOfDate = false;
        pthread_mutex_unlock(&StatusFileOutOfDateLock);
    }
}


int Supervisor::prepareEnvironment (std::vector <std::string> &fpv_conffile, std::vector <std::string> &fpv_classfile)
{
    std::vector <std::string>::iterator fpvi, fpvi_begin, fpvi_end;
    std::vector <std::string> ifaces_to_prepare;
    std::string option, value1, value2, value3;
    std::string iface = "";
    std::string section = "";
    unsigned int section_htb_ceil;

    fpvi = fpv_classfile.begin();                                                
    while (fpvi < fpv_classfile.end()) { 
        option = aux::awk(*fpvi, 1);
        value1 = aux::awk(*fpvi, 2);
        value2 = aux::awk(*fpvi, 3);
        value3 = aux::awk(*fpvi, 4);
        if (!aux::is_in_vector(config->ProperClassesTypes, option)) { fpvi++; continue; } 

        if ((option == "class") || (option == "class-virtual")) {
            section = aux::trim_dev(value1);
            iface = aux::trim_dev(value2);
            if (!aux::is_in_vector(config->RunningSections, section)) { fpvi++; continue; }
        }
        else if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
            section = "";
            iface = aux::trim_dev(value1);
            SAOContainterRequired = true;
        }

        if (!ifaces->isValidSysDev(iface)) { log->error(16, *fpvi); return -1; }

        if (!aux::is_in_vector(ifaces_to_prepare, iface)) {
            ifaces_to_prepare.push_back(iface);
            ifaces->setAsControlled(iface);
            if ((option == "class-wrapper") || ((option == "class-do-not-shape") && (ifaces->isDNShapeMethodSafe(iface)))) {
                ifaces->setHtbDNWrapperClass(iface, true);
            }
        }
        if (section.size() && !ifaces->isInSections(iface, section)) ifaces->addSection(iface, section);
        fpvi++;
    }

    /* reading running sections config */
    for (unsigned int n=0; n < config->RunningSections.size(); n++)
    {
        section = config->RunningSections.at(n);
        if (aux::fpv_section_i(fpvi_begin, fpvi_end, fpv_conffile, section) == -1) {
            return -1;
        }

        fpvi = fpvi_begin;
        while ( fpvi <= fpvi_end )
        {
            option = aux::awk(*fpvi, 1);
            value1 = aux::awk(*fpvi, 2);
            value2 = aux::awk(*fpvi, 3);
            if ((option == "section") && (value1 == "speed")) {
                section_htb_ceil = aux::unit_convert(value2, BITS);
                if ((section_htb_ceil > MAX_RATE) || (section_htb_ceil < MIN_RATE)) { log->error(806, *fpvi); return -1; }
                for (unsigned int m=0; m < ifaces_to_prepare.size(); m++) {
                    iface = ifaces_to_prepare.at(m);
                    if (ifaces->isInSections(iface, section)) {
                        if (ifaces->addToSectionsSpeedSum(iface, section_htb_ceil) == -1) return -1;
                    }
                }
                fpvi = fpvi_end;
            }
            fpvi++;
        }
    }

    if (ifaces->initHtbOnControlled() == -1) return -1;

    return 0;
}



