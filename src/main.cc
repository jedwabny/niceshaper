/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "main.h"

#include <cstdlib>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "aux.h"
#include "config.h"
#include "ifaces.h"
#include "iptables.h"
#include "logger.h"
#include "supervisor.h"
#include "talk.h"
#include "tests.h"

int starter(bool, std::vector <std::string> &, std::vector <std::string> &);
int controller(std::string, std::string, std::string, std::string, int, std::string);
int read_cmdline_params (std::vector <std::string>, bool &, std::string &, std::string &, std::string &, int &, std::string &);
int proceed_global_config (std::vector <std::string> &);
void sig_exit_daemonizer_ok(int);
void sig_exit_daemonizer_error(int);
void sig_exit_supervisor(int);
int get_rid_of_unused(int unused) { return unused; } // To get rid of inproper compiler warnings

// Externs 
class Config *config;
class IfacesMap *ifaces;
class Iptables *ipt;
class Logger *log;
class Sys *sys;
class Tests *test;

// Init extern globals
std::string pidfile = "/var/run/niceshaper.pid";
std::string confdir = "/etc/niceshaper";
std::string conffile = confdir + "/config.conf";
std::string classfile = confdir + "/class.conf";
std::string vardir = "/var/lib/niceshaper";
std::string iptfile = vardir + "/iptsaverestore.ipt";
std::string svinfofile = vardir + "/supervisor.info";

bool g_devmode = false;

// non extern globals
class Supervisor *supervisor = NULL;

int main(int argc, char *argv[])
{
    std::vector <std::string> runtime_params;
    std::string runtime_cmd = "";    
    bool runtime_param_daemon_mode = true;
    std::string runtime_param_remote_address = "";
    std::string runtime_param_remote_password = "";
    std::string runtime_param_status_unit = "";
    int runtime_param_status_watch = 0;
    std::string runtime_param_show_running = "";
    char *env_lang = getenv("LANG");
    std::vector <std::string> fpv_conffile;
    std::vector <std::string> fpv_classfile;

    srand (time(NULL));
    umask (umask(000) | 007);

    log = new Logger;

    if (env_lang != NULL) {
        if (std::string(env_lang) == "pl_PL.UTF-8") log->setLang(PL_UTF8);
        else log->setLang(EN);
    }

    for (int n=0; n<argc; n++) runtime_params.push_back(std::string(argv[n]));

    if (runtime_params.size() <= 1) { log->dumpHelp(); exit(0); }

    runtime_cmd = runtime_params.at(1);

    // Get command line parameters
    if (read_cmdline_params (runtime_params, runtime_param_daemon_mode, runtime_param_remote_address, runtime_param_remote_password, runtime_param_status_unit, runtime_param_status_watch, runtime_param_show_running) == -1) {
        exit(-1);
    }

    if ((getuid() != 0) && (geteuid() != 0) && !((runtime_cmd == "status") && (runtime_param_remote_address.size()))) {
        log->error(404);
        exit(-1);
    }
 
    config = new Config;
    ifaces = new IfacesMap;
    ipt = new Iptables;
    sys = new Sys;
    test = new Tests;

    // Read configuration
    if (config->convertToFpv (confdir, conffile, CONFTYPE, fpv_conffile) == -1) exit (-1);

    if (proceed_global_config(fpv_conffile) == -1) {
        if ((runtime_cmd != "status") && (runtime_cmd != "stats") && (runtime_cmd != "show") && (runtime_cmd != "stop")) exit (-1);
    }

    if (config->removeConfTypeGarbage (fpv_conffile) == -1) exit (-1);

    if ((runtime_cmd == "status") || (runtime_cmd == "stats") || (runtime_cmd == "show") || (runtime_cmd == "stop") || (runtime_cmd == "restart")) {
        if (controller (runtime_cmd, runtime_param_remote_address, runtime_param_remote_password, runtime_param_status_unit, runtime_param_status_watch, runtime_param_show_running) == -1) exit (-1);
        if (runtime_cmd != "restart") exit (0);
    }

    if ((runtime_cmd == "start") || (runtime_cmd == "restart")) {
        if (starter(runtime_param_daemon_mode, fpv_conffile, fpv_classfile) == -1) exit(-1);
        sig_exit_supervisor (SIGTERM);
        exit (0);
    }
    else log->dumpHelp();
    
    return 0;
}

int starter(bool runtime_param_daemon_mode, std::vector <std::string> &fpv_conffile, std::vector <std::string> &fpv_classfile)
{
    int fork_result;

    if (access(pidfile.c_str(), 0) == 0) { log->error(44); return -1; } // NiceShaper already running

    log->info(5);

    if (config->convertToFpv (confdir, classfile, CLASSTYPE, fpv_classfile) == -1) return -1;

    if (config->addIDs(fpv_classfile) == -1) return -1;
    if (config->reOrder(fpv_classfile) == -1) return -1;

    if (runtime_param_daemon_mode) {
        fork_result = fork();
        if (fork_result == -1) {
            return -1;
        }
        else if (fork_result) {
            // SIGUSR1 means proper initialization and SIGUSR2 means some error occurred
            signal (SIGUSR2, sig_exit_daemonizer_error);
            signal (SIGUSR1, sig_exit_daemonizer_ok);
            waitpid (fork_result, NULL, 0);
            // Something went wrong
            exit (-1);
        }
        setsid ();
        chdir ("/");
        usleep(100000);
    }

    supervisor = new Supervisor;

    signal (SIGTERM, sig_exit_supervisor);
    signal (SIGINT, sig_exit_supervisor);

    if (supervisor->init() == -1) {
        if (runtime_param_daemon_mode) kill (getppid(), SIGUSR2);
        sig_exit_supervisor (SIGTERM);
        return -1;
    }

    if (supervisor->entry (fpv_conffile, fpv_classfile) == -1) {
        if (runtime_param_daemon_mode) kill (getppid(), SIGUSR2);
        sig_exit_supervisor (SIGTERM);
        return -1;
    }

    log->info (1);

    if (freopen("/dev/null", "r", stdin) == NULL) return -1;
    if (!g_devmode && runtime_param_daemon_mode) {
        if (freopen("/dev/null", "w", stdout) == NULL) return -1;
        if (freopen("/dev/null", "w", stderr) == NULL) return -1;
        log->setLogOnTerminal (false);
    }

    if (runtime_param_daemon_mode) kill (getppid(), SIGUSR1);

    if (supervisor->loop() == -1) {
        sig_exit_supervisor (SIGTERM);
        return -1;
    }

    return 0;
}

int controller(std::string runtime_cmd, std::string runtime_param_remote_address, std::string runtime_param_remote_password, std::string runtime_param_status_unit, int runtime_param_status_watch, std::string runtime_param_show_running)
{
    std::vector <std::string> result_vector;
    std::string request = "";
    std::string buf = "";
    std::ifstream ifd;
    int dpid;
    int connection_socket;
    struct sockaddr_in address;
    class Talk *talk;
    unsigned int dots_count = 0;

    log->setLogOnTerminal(true);

    if ((runtime_cmd == "status") || (runtime_cmd == "stats") || (runtime_cmd == "show")) 
    {
        talk = new Talk;
        request = runtime_cmd;

        if (runtime_cmd == "show") runtime_param_status_watch = 0;

        if (runtime_param_remote_address.size()) {
            if (runtime_param_remote_password.empty()) { log->error(58); return -1; }
            if (config->setListenerAddress (runtime_param_remote_address) == -1) return -1;
            request += " --password " + runtime_param_remote_password;
        }
        else {
            if (!test->fileExists(pidfile)) { log->error(45); return -1;  }

            // Get listen address and password
            ifd.open(svinfofile.c_str());
            if (ifd.is_open()) {
                getline(ifd, buf);
                ifd.close();
                if (config->setListenerAddress(aux::awk (buf, ":", 1) + ":" + aux::awk (buf, ":", 2)) == -1) return -1;
                if (runtime_param_remote_password.size()) request += " --password " + runtime_param_remote_password;
                else request += " --password " + aux::awk (buf, ":", 3);
            }
            else {
                log->error (201, svinfofile);
                return -1;
            }
        }

        if (runtime_param_status_unit.size()) request += " --unit " + aux::unit_to_str(aux::get_unit(runtime_param_status_unit), 0);
        if (runtime_param_show_running.size()) request += " --running " + runtime_param_show_running;

        do {
            result_vector.clear();

            if ((connection_socket = socket (AF_INET, SOCK_STREAM, 0)) < 0 ) {
                log->error (49, "");
                return -1;
            }

            bzero((char *) &address, sizeof(address));
            address.sin_port = htons(config->getListenerPort());
            address.sin_addr.s_addr = inet_addr(config->getListenerIp().c_str());
            address.sin_family = AF_INET;

            if (connect(connection_socket, (struct sockaddr*)&address, sizeof(struct sockaddr)) < 0) {
                log->error (49, "");
                close (connection_socket);
                return -1;        
            }

            if (talk->sendText (connection_socket, request) == -1) {
                close (connection_socket);
                return -1;
            }

            if (talk->recvTextVector (connection_socket, result_vector) == -1) {
                close (connection_socket);
                return -1;
            }

            close (connection_socket);

            if (runtime_param_status_watch) system ("clear");

            for (unsigned int n=0; n<result_vector.size(); n++ ) {
                std::cout << result_vector.at(n) << std::endl;
            }
        } while (runtime_param_status_watch && (usleep(runtime_param_status_watch*1000000) != -1));

        delete talk;

        exit (0); 
    }
    else if ((runtime_cmd == "stop") || (runtime_cmd == "restart"))
    {
        if (!test->fileExists(pidfile)) { 
            if (runtime_cmd == "restart") {
                log->onTerminal (log->getInfoMessage(45));
                return 0;
            }
            log->error(45); 
            return -1;  
        }

        // Get supervisor pid
        ifd.open(pidfile.c_str());
        if (!ifd) { log->error(45); return -1;  }
        getline(ifd, buf);
        ifd.close();
        dpid = aux::str_to_int(buf);
        if (dpid <= 0) { log->error (45); return -1; }

        log->setDoNotPutNewLineChar (true);
        log->onTerminal (log->getInfoMessage(6));

        kill (dpid, SIGTERM);
        while (!access (pidfile.c_str(), 0))
        {
            log->setDoNotPutNewLineChar (true);
            if (dots_count < config->getStartStopDots()) { 
                log->onTerminal("."); 
                dots_count++; 
            }
            else if (dots_count < (config->getStartStopDots()*2)) { 
                log->onTerminal("\b \b"); 
                dots_count++; 
                continue;
            }
            else {
                dots_count=0;
                continue;
            }
            usleep (100000);
        }
        log->onTerminal (log->getInfoMessage(2));
        if (runtime_cmd == "restart") return 0;
    }
    else return -1;
    
    exit (0);
}

int read_cmdline_params (std::vector <std::string> runtime_params, bool &daemon_mode, std::string &remote_address, std::string &remote_password, std::string &status_unit, int &status_watch, std::string &show_running)
{
    bool is_set_conffile = false;
    bool is_set_classfile = false;
    std::string param = "", value = "";

    for (unsigned int n=2; n<runtime_params.size(); n++) {
        param = runtime_params.at(n);
        if (runtime_params.at(n) != "--no-daemon") {
            if ((n+1) >= runtime_params.size()) {
                log->error (28, runtime_params.at(n)); 
                return -1; 
            }
            value = runtime_params.at(++n);
        }

        if (param == "--no-daemon") { 
            daemon_mode = false; 
        }
        else if (param == "--confdir") {
            confdir = value;
            if (!is_set_conffile) conffile = confdir + "/config.conf";
            if (!is_set_classfile) classfile = confdir + "/class.conf";
        }
        else if (param == "--conffile") { 
            conffile = value;
            is_set_conffile = true;
        }
        else if (param == "--classfile") { 
            classfile = value;
            is_set_classfile = true;
        }                                                   
        else if (param == "--remote") { 
            remote_address = value;
        }
        else if (param == "--password") { 
            remote_password = value;
        }
        else if (param == "--unit") { 
            status_unit = value;
        }
        else if (param == "--watch") { 
            status_watch = aux::str_to_int(value);
            if ((status_watch < 1) || (status_watch > 60)) { log->error (28, param); return -1; }
        }
        else if (param == "--running") { 
            show_running = value;
            if ((value != "config") && (value != "classes")) { log->error (28, param + " " + value); return -1; }
        }
        else { log->error (28, param); return -1; }    
    }

    return 0;
}

int proceed_global_config (std::vector <std::string> &fpv_conffile)
{
    std::vector <std::string>::iterator fpvi, fpvi_begin, fpvi_end;
    std::string option, param, value, dev;

    if (aux::fpv_section_i( fpvi_begin, fpvi_end, fpv_conffile, "global" ) == -1 ) return -1;;

    /*fpvi = fpvi_begin;                                                
        while ( fpvi <= fpvi_end ) {                                                                        
            std::cout << "cf:" << *fpvi << std::endl;
            fpvi++;                                                                                    
    }*/

    fpvi=fpvi_begin;
    while (fpvi <= fpvi_end) {
        option = aux::awk(*fpvi, 1);
        param = aux::awk(*fpvi, 2);
        value = aux::awk(*fpvi, 3);

        if (option == "run") {
            if (param.size() > MAX_SECTION_NAME_SIZE) { log->error(54, *fpvi); return -1; }
            config->addRunningSection(param);
            if (config->RunningSections.size() > MAX_SECTIONS_COUNT) { log->error(809, aux::int_to_str(MAX_SECTIONS_COUNT)); return -1; }
        }
        else if (option == "mark-on-ifaces") 
        {
            dev = aux::trim_dev(param);
            if (!ifaces->isValidSysDev(dev)) { log->error (16, *fpvi); return -1; }
            ifaces->setTcFilterType(dev, FW);
        }
        else if (aux::awk(option, "-", 1) == "iface") {
            dev = aux::trim_dev(option.substr(option.find("-")+1, std::string::npos));
            if (!ifaces->isValidSysDev(dev)) { log->error (16, *fpvi); return -1; }
            if (param == "speed") {
                if ((aux::unit_convert(value, BITS) > MAX_RATE) || (aux::unit_convert(value, BITS) < MIN_RATE)) { log->error(806, *fpvi); return -1; }
                ifaces->setSpeed(dev, aux::unit_convert(value, BITS));
            }
            else if (param == "do-not-shape-method") {
                if (value == "safe") ifaces->setDNShapeMethodSafe(dev, true);
                else if (value == "full-throttle") ifaces->setDNShapeMethodSafe(dev, false);
                else { log->error ( 11, *fpvi ); return -1; }
            }
            else if (param == "unclassified-method") {
                if (value == "fallback-class") ifaces->setUnclassifiedMethodFallbackClass(dev, true);
                else if (value == "do-not-control") ifaces->setUnclassifiedMethodFallbackClass(dev, false);
                else { log->error ( 11, *fpvi ); return -1; }
            }
            else if (param == "fallback-rate") {
                if ((aux::unit_convert(value, BITS) > MAX_RATE) || (aux::unit_convert(value, BITS) < MIN_RATE)) { log->error(806, *fpvi); return -1; }
                ifaces->setFallbackRate(dev, aux::unit_convert(value, BITS));
            }   
            else if (param == "mode")
            {
                if (value == "download") {
                    if (ifaces->setFlowDirection(dev, DWLOAD) == -1) { log->error (866, *fpvi); return -1; }
                }
                else if (value == "upload") {
                    if (ifaces->setFlowDirection(dev, UPLOAD) == -1) { log->error (866, *fpvi); return -1; }
                }
                else { log->error (11, *fpvi); return -1; }
            } 
            else { log->error ( 11, *fpvi ); return -1; }
        }
        else if ( option == "lang" ) {  
            if ( param == "pl" ) log->setLang(PL_UTF8);  
            else if ( param == "en" ) log->setLang(EN);
            else { log->error ( 11, *fpvi ); return -1; }
        }
        else if ((option == "status") || (option == "stats")) {
            if (option == "stats") log->warning(18);

            if ( param == "unit" ) 
            {
                config->setStatusUnit(aux::get_unit(value));
            }
            else if ( param == "classes" )
            {
                if ( value == "all" ) config->setStatusShowClasses(SC_ALL);
                else if ( value == "active" ) config->setStatusShowClasses(SC_ACTIVE);
                else if ( value == "working" ) config->setStatusShowClasses(SC_WORKING);
                else if ( value == "no" ) config->setStatusShowClasses(SC_FALSE);
                else { log->error(11, *fpvi); }
            }
            else if ( param == "sum" )
            {
                if ( value == "top" ) config->setStatusShowSum(SS_TOP);
                else if ( value == "bottom" ) config->setStatusShowSum(SS_BOTTOM);
                else if ( value == "no" ) config->setStatusShowSum(SS_FALSE);
                else { log->error( 11, *fpvi ); }
            }
            else if ( param == "do-not-shape" )
            {
                if ( value == "yes" ) config->setStatusShowDoNotShape(true);
                else if ( value == "no" ) config->setStatusShowDoNotShape(false);
                else log->error ( 11, *fpvi );
            }
            else if ( param == "listen" ) {
                log->error(153, *fpvi); 
                return -1; 
            }
            else if (param == "password") {
                log->error(154, *fpvi); 
                return -1; 
            }
            else if (param == "file") 
            {
                if ((value == "no") || value.empty()) config->setStatusFilePath("");
                else config->setStatusFilePath(value);
            }
            else if (param == "file-owner") {
                config->setStatusFileOwner(value);
            }
            else if (param == "file-group") {
                config->setStatusFileGroup(value);
            }
            else if (param == "file-mode") {
                config->setStatusFileMode(value);
            }
            else if (param == "file-rewrite") {
                config->setStatusFileRewrite(aux::str_to_int(value));
                if ((config->getStatusFileRewrite() < 1) || (config->getStatusFileRewrite() > 3600)) {
                    log->error(805, *fpvi);
                    return -1;
                }
            }
            else if ((param == "owner") || (param == "group") || (param == "mode") || (param == "rewrite")) {
                log->error(155, *fpvi);
                return -1;
            }
        } 
        else if ( option == "listen" ) {
            if ( param == "address" ) {
                if (config->setListenerAddress(value) == -1) return -1;
            }
            else if (param == "password") {
                config->setListenerPassword(value);
            }
        } 
        else if ( option == "log" ) {
            if ( param == "terminal" ) {
                if ( value == "yes" ) {
                    log->setLogOnTerminal(true);
                }
                else if ( value == "no" ) {
                    log->setLogOnTerminal(false);
                }
                else {
                    log->error ( 11, *fpvi );
                    log->setLogOnTerminal(true);
                }
            }   
            else if ( param == "syslog" ) {
                if ( value == "yes" ) {
                    log->setLogToSyslog(true);
                }
                else if ( value == "no" ) {
                    log->setLogToSyslog(false);
                }
                else {
                    log->error ( 11, *fpvi );
                    log->setLogToSyslog(true);
                }
            }   
            else if ( param == "file" ) {
                if ( value == "no" ) {
                    log->setLogFile("");
                }
                else {
                    log->setLogFile(value);
                }
            }   
        }
        else if (option == "iptables") 
        {
            if (param == "download-hook") {
                if (ipt->setHook(DWLOAD, value) == -1) { return -1; }
            }
            else if (param == "upload-hook") {
                if (ipt->setHook(UPLOAD, value) == -1) { return -1; }
            }
            else if (param == "target") {
                if (ipt->setTarget(value) == -1) { log->error(11, *fpvi); return -1; }
            }
            else if (param == "imq-autoredirect") {
                if (value == "yes") config->setImqAutoRedirect(true);
                else if (value == "no") config->setImqAutoRedirect(false);
                else { log->error(11, *fpvi); }
            }
            else { log->error( 11, *fpvi ); }
        }       
        else if (option == "debug")
        {
            if (param == "iptables") ipt->setDebug(true);
            else if (param == "iproute") { log->error(158, "debug iproute"); return -1; }
            else { log->error( 11, *fpvi ); }
        } 
        else if (option == "fallback") {
            if (param == "iptables") ipt->setFallback(true);
            else if (param == "iproute") { log->error(158, "fallback iproute"); return -1; }
            else { log->error(11, *fpvi); return -1; }
        }
        else if (option == "local-subnets")
        {
            if (config->addLocalSubnet(param) == -1) { log->error(59, *fpvi); return -1; }
        }
        else if (option == "auto-hosts") {
            if (param.size() > MAX_SECTION_NAME_SIZE) { log->error(54, *fpvi); return -1; }
            dev = aux::trim_dev(value);
            if (!ifaces->isValidSysDev(dev)) { log->error (16, *fpvi); return -1; }
            config->addAutoHostsBasis(param, dev);
        }

        fpvi++;
    }
    return 0;
}

void sig_exit_daemonizer_ok(int sig)
{
    signal(SIGUSR1, sig_exit_daemonizer_ok);

    get_rid_of_unused (sig);

    exit (0);
}

void sig_exit_daemonizer_error(int sig)
{
    signal(SIGUSR2, sig_exit_daemonizer_error);

    get_rid_of_unused (sig);

    exit (-1);
}

void sig_exit_supervisor(int sig)
{
    signal(SIGTERM, sig_exit_supervisor);
    signal(SIGINT, sig_exit_supervisor);

    get_rid_of_unused (sig);

    log->info(6);

    delete supervisor;

    log->info(2);

    usleep(100000);

    if (log->getErrorLogged()) exit (-1);

    exit(0);
}


