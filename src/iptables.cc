/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "iptables.h"

#include <stdlib.h>
#include <unistd.h>

#include <string>
#include <vector>
#include <fstream>

#include "main.h"
#include "aux.h"
#include "config.h"
#include "logger.h"
#include "ifaces.h"
#include "tests.h"

Iptables::Iptables()
{
    HookDwload = "POSTROUTING";
    HookUpload = "POSTROUTING";
    ChainDwload = "ns_dwload";
    ChainUpload = "ns_upload";
    Target = "ACCEPT";
    RequiredForDwload = false;
    RequiredForUpload = false;
    RequiredForCheckDwload = false;
    RequiredForCheckUpload = false;
    Debug = false;
    Fallback = false;
    Initialized = false;
    CacheExpireUsec = 99999; // 0.1s
    //
    ProperHooks.push_back("PREROUTING");
    ProperHooks.push_back("POSTROUTING");
    //
    ProperTargets.push_back("ACCEPT");
    ProperTargets.push_back("RETURN");
}

Iptables::~Iptables()
{
    clean();
}

int Iptables::clean()
{
    if (!RequiredForDwload && !RequiredForUpload) return 0;

    if (!Initialized) return 0;

    for (unsigned int n=0; n<RulesDestroy.size(); n++) { 
        execSysCmd("iptables -t mangle " + RulesDestroy.at(n) + " 2>/dev/null");
    }

    Initialized = false;

    Rules.clear();
    RulesDestroy.clear();
    AssignHelperDwload.clear();
    AssignHelperUpload.clear();

    return 0;
}

int Iptables::setHook(EnumFlowDirection flow_direction, std::string hook)
{
    if (!aux::is_in_vector(ProperHooks, hook)) {
        log->error(701, hook);
        return -1; 
    }

    if (flow_direction == DWLOAD) HookDwload = hook;
    else if (flow_direction == UPLOAD) HookUpload = hook;

    return 0;
}

int Iptables::setChain(EnumFlowDirection flow_direction, std::string chain)
{
    if (flow_direction == DWLOAD) ChainDwload = chain;
    else if (flow_direction == UPLOAD) ChainUpload = chain;

    return 0;
}

int Iptables::setTarget(std::string target)
{
    if (!aux::is_in_vector(ProperTargets, target)) {
        log->error(706, target);
        return -1; 
    }

    Target = target;

    return 0;
}

void Iptables::setDebug(bool debug_ipt) 
{ 
    Debug = debug_ipt; 
}

void Iptables::setFallback(bool ipt_fallback) 
{ 
    Fallback = ipt_fallback; 
}

void Iptables::setRequirementsIfRequired(bool required_for_dwload, bool required_for_check_dwload, bool required_for_upload, bool required_for_check_upload)
{
    if (required_for_dwload) RequiredForDwload = true;
    if (required_for_upload) RequiredForUpload = true;
    if (required_for_check_dwload) RequiredForCheckDwload = true;
    if (required_for_check_upload) RequiredForCheckUpload = true;
}

int Iptables::execSysCmd(std::string command)
{
    if (Debug) log->info(7, command);

    if (system(command.c_str()) == -1) return -1;

    return 0;
}

int Iptables::prepare(std::vector <std::string> &fpv_class_file, std::vector <Worker *> &workers)
{
    std::string buf;

    if (!RequiredForDwload && !RequiredForUpload) return 0;

    if (RequiredForDwload) Rules.push_back(" -N " + ChainDwload); 
    if (RequiredForUpload) Rules.push_back(" -N " + ChainUpload);

    for (unsigned int n=0; n<config->LocalSubnets.size(); n++) {
        if (RequiredForDwload) {
            buf = HookDwload + " -d " + config->LocalSubnets.at(n) + " -j " + ChainDwload;
            Rules.push_back(" -A " + buf);
            RulesDestroy.push_back(" -D " + buf);
        }
        if (RequiredForUpload) {
            buf = HookUpload + " -s "  + config->LocalSubnets.at(n) + " -j " + ChainUpload;
            Rules.push_back(" -A " + buf);
            RulesDestroy.push_back(" -D " + buf);
        }
    }

    if (prepareRules(fpv_class_file, workers) == -1) { log->error(799); return -1; }

    if (RequiredForDwload) {
        RulesDestroy.push_back(" -F " + ChainDwload);
        RulesDestroy.push_back(" -X " + ChainDwload);
    }
    if (RequiredForUpload) {
        RulesDestroy.push_back(" -F " + ChainUpload);
        RulesDestroy.push_back(" -X " + ChainUpload);
    }

    return 0;
}

int Iptables::init()
{
    std::ofstream ofd;
    FILE *fp;
    char cbuf[MAX_LONG_BUF_SIZE];
    unsigned int bsize = 0;
    std::string buf;

    if (!RequiredForDwload && !RequiredForUpload) return 0;

    if (Fallback) log->setDoNotPutNewLineChar (true);

    log->info(10);

    // Clear iptables from rubbish remains
    buf = "";
    do {
        if (buf.empty()) buf=ChainDwload;
        else buf=ChainUpload;
        execSysCmd ("for n in `iptables -t mangle -L PREROUTING -nv --line-numbers | grep " + buf + " | awk '{print $1}' | sort -r`; do iptables -t mangle -D PREROUTING $n; done");
        execSysCmd ("for n in `iptables -t mangle -L POSTROUTING -nv --line-numbers | grep " + buf + " | awk '{print $1}' | sort -r`; do iptables -t mangle -D POSTROUTING $n; done");
        execSysCmd ("for n in `iptables -t mangle -L -nv | grep 'Chain " + buf + "' | awk '{print $2}'`; do iptables -t mangle -F $n ; iptables -t mangle -X $n; done");
    } while (buf != ChainUpload);        

    Initialized = true;

    TVChainUploadPrev.tv_sec = 0;
    TVChainDwloadPrev.tv_sec = 0;

    if (!Fallback) {
        ofd.open(iptfile.c_str());
        if (ofd.is_open()) {
            fp = popen("iptables-save -t mangle", "r");
            if (!fp) {
                log->error(0);
                return -1; 
            }
            while (fgets(cbuf, MAX_LONG_BUF_SIZE, fp)) {
                buf = aux::trim_legacy(std::string(cbuf));
                if (buf.find_first_of("#") != std::string::npos) buf.erase(buf.find_first_of("#"));
                if (buf == "COMMIT") continue;  
                ofd << buf << std::endl;
            }
            pclose(fp);

            for (unsigned int i=0; i<Rules.size(); i++) {
                ofd << aux::trim_legacy(Rules.at(i)) << std::endl;
            }

            ofd << "COMMIT" << std::endl;

            ofd.flush();
            ofd.close();

            // Apply 
            if (execSysCmd("iptables-restore < " + iptfile) == -1) { log->error(705, iptfile); return -1; }
            if (!Debug) unlink (iptfile.c_str());
            else log->info (100, iptfile);
        }
        else {
            log->warning(15, iptfile);
            Fallback = true;
        }
    }

    if (Fallback) 
    {
        if (!config->getStartStopDots()) { log->error(999, "!config->getStartStopDots()"); return -1; }
        for (unsigned int i=0; i<Rules.size(); i++) {
            if ((Rules.size() < config->getStartStopDots()) || !(i%(Rules.size()/config->getStartStopDots()))) {
                while (bsize) {
                    log->setDoNotPutNewLineChar (true);
                    log->onTerminal ("\b");
                    bsize--;
                }
                buf = aux::int_to_str(static_cast<unsigned int>(i*100/Rules.size()));
                bsize = buf.size()+3;
                
                log->setDoNotPutNewLineChar (true);
                log->onTerminal (".["+buf+"%]");
            }
            execSysCmd ("iptables -t mangle " + Rules.at(i));
        }
        if (bsize) {
            while (bsize) {
                log->setDoNotPutNewLineChar (true);
                log->onTerminal ("\b");
                bsize--;
            }
        }
        log->setDoNotPutNewLineChar (true);
        log->onTerminal ("[100%]");

    }

    return 0;
}

int Iptables::prepareRules(std::vector <std::string> &fpv_class_file, std::vector <Worker *> &workers)
{
    std::string buf, option;
    std::string class_section, class_dev, class_name;
    EnumNsClassType class_type;
    EnumFlowDirection class_flow_direction;
    unsigned int worker_vid;

    for (unsigned int i=0; i<fpv_class_file.size(); i++)
    {
        buf = fpv_class_file.at(i);
        option = aux::awk(buf, 1);
        if ((option == "class") || (option == "class-virtual")) {
            class_section = aux::awk(buf, 2);
            class_dev = aux::trim_dev(aux::awk(buf, 3));
            class_name = aux::awk(buf, 4);
            worker_vid = 1;
            while (workers.at(worker_vid)->getSectionName() != class_section) worker_vid++;
            class_flow_direction = workers.at(worker_vid)->getFlowDirection(); 
            if (option == "class") class_type = STANDARD_CLASS;
            else if (option == "class-virtual") class_type = VIRTUAL;
        }
        else if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
            class_section = "";
            class_dev = aux::trim_dev(aux::awk(buf, 2));
            class_name = aux::awk(buf, 3);
            worker_vid = 0;
            class_flow_direction = ifaces->getFlowDirection(class_dev);
            if (class_flow_direction == UNSPEC) { log->error(867, buf); return -1; }
            if (option == "class-wrapper") class_type = WRAPPER;
            else if (option == "class-do-not-shape") class_type = DONOTSHAPE;
        }
        else if (option == "match") {
            if ((class_flow_direction != DWLOAD) && (class_flow_direction != UPLOAD)) { log->error(998, buf); return -1; }
            if (genRulesFromNSMatch(buf, worker_vid, class_type, class_flow_direction, class_dev) == -1) return -1;
        }
    }

    return 0;
}

int Iptables::genRulesFromNSMatch(std::string src, unsigned int worker_vid, enum EnumNsClassType class_type, EnumFlowDirection class_flow_direction, std::string class_iface)
{
    std::string buf;
    std::string filter = "";
    std::string target_chain = "";
    std::string hook_behaviour = "";
    std::string rule_local = "";
    std::string rule_mark = "";
    std::string rule_imq = "";
    std::string rule_finalize = "";
    bool rule_local_helper_req = false;
    unsigned int rules_count = 0;   

    if ((class_flow_direction == DWLOAD) && (RequiredForDwload)) {
        target_chain = ChainDwload;
        hook_behaviour = HookDwload;
        AssignHelperDwload.push_back(worker_vid);
    }
    else if ((class_flow_direction == UPLOAD) && (RequiredForUpload)) {
        target_chain = ChainUpload;
        hook_behaviour = HookUpload;
        AssignHelperUpload.push_back(worker_vid);
    }
    else return 0;

    if (aux::value_of_param(src, "to-local").size() && aux::value_of_param(src, "from-local").size()) {
        log->error(68, src);
        return -1;
    }

    if (aux::value_of_param(src, "to-local").size()) {
        if (hook_behaviour != "PREROUTING") {
            hook_behaviour = "PREROUTING";
            rule_local_helper_req = true;
        }
        else if ((hook_behaviour == "PREROUTING") && (class_flow_direction == DWLOAD)) {
            rule_local_helper_req = true;
        }
    }
    else if (aux::value_of_param(src, "from-local").size()) {
        if (hook_behaviour != "POSTROUTING") {
            hook_behaviour = "POSTROUTING";
            rule_local_helper_req = true;
        }
        else if ((hook_behaviour == "POSTROUTING") && (class_flow_direction == UPLOAD)) {
            rule_local_helper_req = true;
        }
    }

    if (genFilterFromNSMatch(src, class_flow_direction, hook_behaviour, class_iface, "", filter) == -1) return -1;

    if (rule_local_helper_req) {
        rule_local = hook_behaviour + " " + filter + " -j " + target_chain;
    }

    if (class_type == VIRTUAL) {
        // For type virtual do not mark, do not make redirect to imq interface, and do not make return from chain
        rule_finalize = " " + target_chain + " " + filter;
    }
    else {
        // Marking rule
        if (ifaces->tcFilterType(class_iface) == FW) {
            rule_mark = " " + target_chain + " " + filter + " -j MARK --set-mark " + aux::value_of_param(src, "_set-mark_");
            if (genFilterFromNSMatch(src, class_flow_direction, hook_behaviour, class_iface, aux::value_of_param(src, "_set-mark_"), filter) == -1) return -1;
        }

        // IMQ redirect rule
        if (test->ifaceIsImq(class_iface) && config->getImqAutoRedirect()) {
            rule_imq = " " + target_chain + " " + filter + " -j IMQ --todev " + &(class_iface[3]);
        }

        // Finally return from chain
        rule_finalize = " " + target_chain + " " + filter + " -j " + Target;
    }

    if (rule_local.size()) {
        Rules.push_back(std::string(" -A ") + rule_local);
        RulesDestroy.push_back(" -D " + rule_local);
    }

    if (rule_mark.size()) {
        Rules.push_back(std::string(" -A ") + rule_mark);
        rules_count++;
    }

    if (rule_imq.size()) {
        Rules.push_back(std::string(" -A ") + rule_imq);
        rules_count++;
    }

    Rules.push_back(std::string(" -A ") + rule_finalize);
    rules_count++;

    if (class_flow_direction == DWLOAD) AssignHelperDwload.push_back(rules_count);
    else if (class_flow_direction == UPLOAD) AssignHelperUpload.push_back(rules_count);

    return 0;
}

int Iptables::genFilterFromNSMatch (std::string src, EnumFlowDirection class_flow_direction, std::string hook_behaviour, std::string class_iface, std::string override_test_mark, std::string &result)
{
    std::string addr, mask;
    std::string param, value;
    bool proto_defined = false;
    bool from_local_defined = false;
    bool to_local_defined = false;
    bool filter_iface_required = false;
    std::string filter_iface;
    unsigned int pos;

    result = "";

    if (aux::awk(src, 1) != "match") { log->error(60, src); return -1; }

    if (test->ifaceIsImq(class_iface)) filter_iface_required = true;

    // filters which need to be ahead of others 
    pos=1;
    while (aux::awk(src, ++pos).size()) { 
        param = aux::awk(src, pos);
        value = aux::awk(src, ++pos);
        result += " ";  // Leading whitespace       
        if (param == "proto") {
            if ((value != "tcp") && (value != "udp") && (value != "icmp")) { log->error(67, src); return -1; }
            result += "-p " + value;
            proto_defined = true;
        }
        else if (param == "from-local") {
            if (!test->validIp(value)) { 
                log->error(29, value);
                log->error(60, src); 
                return -1; 
            }
            from_local_defined = true;
            result += " -s " + value;
        }
        else if (param == "to-local") {
            if (!test->validIp(value)) { 
                log->error(29, value); 
                log->error(60, src);
                return -1; 
            }
            if (!test->ifaceIsImq(class_iface)) { 
                log->error(865, src); 
                return -1; 
            }
            to_local_defined = true;
            result += " -d " + value;
        }

        result += " ";  // Trailing whitespace  
    }

    if (from_local_defined && to_local_defined) { log->error(60, src); return -1; }

    // filters which order does not matter
    pos=1;
    while (aux::awk(src, ++pos).size()) { 
        param = aux::awk(src, pos);
        value = aux::awk(src, ++pos);
        result += " ";  // Leading whitespace       
        if (param == "in-iface") {
            filter_iface = value;
            if (!ifaces->isValidSysDev(filter_iface)) { log->error(16, src); return -1; }
            if (hook_behaviour == "POSTROUTING") {
                log->error(72, src);
                return -1;
            }
            if (!test->ifaceIsImq(class_iface) && (class_iface == filter_iface)) {
                log->error(76, src);
                return -1;
            }
            result += " -i " + filter_iface;
        }
        else if (param == "out-iface") {
            filter_iface = value;
            if (!ifaces->isValidSysDev(filter_iface)) { log->error(16, src); return -1; }
            if (hook_behaviour == "PREROUTING") {
                log->error(73, src);
                return -1;
            }
            if (!test->ifaceIsImq(class_iface) && (class_iface != filter_iface)) {
                log->error(75, src);
                return -1;
            }
            result += " -o " + filter_iface;
        }
        else if ((param == "srcip") || ((param == "_auto-srcip-dstip_") && (class_flow_direction == UPLOAD))) {
            if (from_local_defined) { log->error(65, src); return -1; }
            if (aux::split_ip(value, addr, mask) == -1) return -1;
            result += " -s " + std::string(addr) + "/" + std::string(mask);    
        }
        else if ((param == "dstip") || ((param == "_auto-srcip-dstip_") && (class_flow_direction == DWLOAD))) {
            if (to_local_defined) { log->error(64, src); return -1; }
            if (aux::split_ip(value, addr, mask) == -1) return -1;
            result += " -d " + std::string(addr) + "/" + std::string(mask);    
        }
        else if ( param == "not-srcip" ) {
            if (from_local_defined) { log->error(65, src); return -1; }
            if (aux::split_ip(value, addr, mask) == -1 ) return -1;
            result += " -s ! " + std::string(addr) + "/" + std::string(mask);
        }
        else if ( param == "not-dstip" ) {
            if (to_local_defined) { log->error(64, src); return -1; }
            if (aux::split_ip(value, addr, mask) == -1 ) return -1;
            result += " -d ! " + std::string(addr) + "/" + std::string(mask);
        }
        else if (( param == "srcport" ) || ( param == "sport" )) {
            if ( !proto_defined ) {
                log->error(62, src); 
                return -1; 
            }
            result += "--sport " + value;
        }
        else if (( param == "dstport" ) || ( param == "dport" )) {
            if ( !proto_defined ) {
                log->error(62, src); 
                return -1; 
            }
            result += "--dport " + value;
        }
        else if (( param == "not-srcport" ) || ( param == "not-sport" )) {
            if ( !proto_defined ) {
                log->error(62, src); 
                return -1; 
            }
            result += "--sport ! " + value;
        }
        else if (( param == "not-dstport" ) || ( param == "not-dport" )) {
            if ( !proto_defined ) {
                log->error(62, src); 
                return -1; 
            }
            result += "--dport ! " + value;
        }
        else if ( param == "length" ) {
            result += "-m length --length " + value;
        }
        else if ( param == "state" ) {
            if (( value != "new") && ( value != "established") && ( value != "related") && ( value != "invalid") && ( value != "untracked")) {
                log->error(61, src); 
                return -1; 
            }
            result += "-m state --state " + value;
        }
        else if ( param == "tos" ) {
            result += "-m tos --tos " + value;
        }
        else if ( param == "ttl-lower" ) {
            result += "-m ttl --ttl-lt " + value;
        }
        else if ( param == "ttl-greater" ) {
            result +=  "-m ttl --ttl-gt " + value;
        }
        else if ( param == "ttl" ) {
            result += "-m ttl --ttl " + value;
        }    
        else if ( param == "mark" ) {
            if (override_test_mark.empty()) result += "-m mark --mark " + value;
            else result += "-m mark --mark " + override_test_mark;
        }   
        else if (( param != "proto" ) && ( param != "_set-mark_" )
                && ( param != "_filterid_" ) && ( param != "to-local" ) 
                && ( param != "from-local" ) && ( param != "use-for-fw" )) {
            log->error (60, src);
            log->error (101, param);
            return -1;     
        }   
        result += " ";  // Trailing whitespace  
    }

    if (filter_iface_required && filter_iface.empty()) {
        log->error(74, src); 
        return -1; 
    }

    if (filter_iface.empty()) {
        if (hook_behaviour == "PREROUTING") result += " ! -i " + class_iface;
        else if (hook_behaviour == "POSTROUTING") result += " -o " + class_iface;
    }

    return 0;
}


int Iptables::checkTraffic(EnumFlowDirection flow_direction, unsigned int worker_vid, std::vector <__u64> &section_ordered_counters, std::vector <__u64> &section_ordered_counters_dnsw)
{
    char cbuf[MAX_LONG_BUF_SIZE];
    std::string chain;
    std::vector <unsigned int> *assign_helper_ptr;
    std::vector <std::string> *chain_raw_counters_ptr;
    struct timeval tv_curr, *tv_prev_ptr;
    unsigned int duration_time;
    unsigned int chain_raw_counters_pos;
    FILE *fp;

    if (flow_direction == DWLOAD) {
        chain = ChainDwload;
        tv_prev_ptr = &TVChainDwloadPrev;
        assign_helper_ptr = &AssignHelperDwload;
        chain_raw_counters_ptr = &ChainRawCountersDwload;
    }   
    else if (flow_direction == UPLOAD) {
        chain = ChainUpload;
        tv_prev_ptr = &TVChainUploadPrev;
        assign_helper_ptr = &AssignHelperUpload;
        chain_raw_counters_ptr = &ChainRawCountersUpload;
    }
    else {
        log->error(999, "int Iptables::checkTraffic");
        return -1;    
    }

    gettimeofday (&tv_curr, NULL);    
    duration_time = (tv_curr.tv_sec-(*tv_prev_ptr).tv_sec)*1000000+tv_curr.tv_usec-(*tv_prev_ptr).tv_usec;

    if (duration_time >= CacheExpireUsec) {
        *tv_prev_ptr = tv_curr;
        (*chain_raw_counters_ptr).clear();
        fp = popen(("iptables -t mangle -L " + chain + " -vnx").c_str(), "r");
        for (unsigned int n=1; n<=2; n++) {
            if (fgets(cbuf, MAX_LONG_BUF_SIZE, fp) == NULL) {
                log->error(12); 
                log->setReqRecoverIpt(true);
                pclose(fp);
                return -1;
            }
        }

        while (fgets(cbuf, MAX_LONG_BUF_SIZE, fp)) {
            (*chain_raw_counters_ptr).push_back(aux::awk(std::string(cbuf), 2));
        }
        pclose(fp);
    }

    chain_raw_counters_pos = 0;

    for (unsigned int n=0; n<assign_helper_ptr->size(); n++)
    {
        if ((chain_raw_counters_pos + assign_helper_ptr->at(n+1)) > chain_raw_counters_ptr->size()) { 
            log->error (12, chain);
            log->setReqRecoverIpt(true); 
            return -1; 
        }

        if (assign_helper_ptr->at(n) == worker_vid) {
            section_ordered_counters.push_back(aux::str_to_u64(chain_raw_counters_ptr->at(chain_raw_counters_pos)));
        }
        else if (config->getStatusShowDoNotShape() && (assign_helper_ptr->at(n) == 0)) {
            section_ordered_counters_dnsw.push_back(aux::str_to_u64(chain_raw_counters_ptr->at(chain_raw_counters_pos)));
        }

        n++;
        chain_raw_counters_pos += assign_helper_ptr->at(n);
    }

    if (chain_raw_counters_pos < chain_raw_counters_ptr->size()) { 
        log->error (12, chain); 
        log->setReqRecoverIpt(true);
        return -1; 
    }

    return 0;
}
