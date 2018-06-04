/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "config.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <iostream>
#include <fstream>

#include "main.h"
#include "aux.h"
#include "logger.h"
#include "ifaces.h"
#include "tests.h"

Config::Config ()
{
    ListenerIp = "127.0.0.1";
    ListenerPort = 6423;
    ListenerPassword = "";
    StatusUnit = KBITS;
    StatusFilePath = "";
    StatusFileOwner = "root";
    StatusFileGroup = "root";     
    StatusFileMode = "0644";
    StatusFileRewrite = 30;
    StatusShowClasses = SC_WORKING;
    StatusShowSum = SS_BOTTOM;
    StatusShowDoNotShape = false;
    ImqAutoRedirect = true;
    AutoHostsBasis = "";
    
    // Create random password
    std::string random_password_chars = "abcdefghyjklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUWXYZ1234567890";
    for (int n=0; n < 12; n++) {
        ListenerPassword += random_password_chars.at(rand() % random_password_chars.size());
    }

    RunningSections.clear();
    LocalSubnets.clear();

    ProperClassesTypes.clear();
    ProperClassesTypes.push_back ("class");
    ProperClassesTypes.push_back ("class-virtual");
    ProperClassesTypes.push_back ("class-wrapper");
    ProperClassesTypes.push_back ("class-do-not-shape");

    FilterTestsNeedFW.clear();
    FilterTestsNeedFW.push_back ("not-srcip");
    FilterTestsNeedFW.push_back ("not-dstip");
    FilterTestsNeedFW.push_back ("not-srcport");
    FilterTestsNeedFW.push_back ("not-sport");
    FilterTestsNeedFW.push_back ("not-dstport");
    FilterTestsNeedFW.push_back ("not-dport");
    FilterTestsNeedFW.push_back ("length");
    FilterTestsNeedFW.push_back ("state");
    FilterTestsNeedFW.push_back ("tos");
    FilterTestsNeedFW.push_back ("ttl-lower");
    FilterTestsNeedFW.push_back ("ttl-greater");
    FilterTestsNeedFW.push_back ("ttl");
    FilterTestsNeedFW.push_back ("mark");

    FWMarksProtectedFully.clear();
    FWMarksProtectedPartly.clear();

    ReqRecoverWait = 60;
    StartStopDots = 10;
}

Config::~Config ()
{
    //
}

std::string Config::getLine(std::ifstream &src_file)
{
    bool state_store = true, potential_block_comment_tag = false, state_block_comment = false;
    int buf_counter = 0;    
    char sbuf[MAX_LONG_BUF_SIZE];
    char cbuf;
    std::string buf;

    sbuf[0]=0;
    while (src_file.read(&cbuf, 1))
    {
        // completing one line
        // ASCII: '<'=60, '#'=35, '>'=62
        if (!state_block_comment) {
            if (potential_block_comment_tag) {
                if ((cbuf == 35) && state_store ) {
                    state_block_comment = true;
                    buf_counter--;
                    sbuf[buf_counter]=0;
                    continue;
                }
                potential_block_comment_tag = false;
            }
            if ( cbuf == 60 ) potential_block_comment_tag = true;       
        }
        else if ( state_block_comment ) {
            if ( potential_block_comment_tag ) {
                if ( cbuf == 62 ) {
                    state_block_comment = false;
                    state_store = true;
                    sbuf[buf_counter]=0;
                    continue;
                }
                potential_block_comment_tag = false;
            }
            if ( cbuf == 35 ) potential_block_comment_tag = true;
        }

        if (cbuf == 35) state_store = false;    // '#'
        if (cbuf == 59) {                       // ';'
            if (state_store) cbuf = 10;
            else cbuf = 35;
        }
        if (cbuf == 10) state_store = true;     // 'NewLine'

        if ( state_store && !state_block_comment)
        {
            sbuf[buf_counter]=cbuf;
            buf_counter++;
        }

        if ( cbuf != 10 ) continue; 
        // end of completing line

        sbuf[buf_counter]=0;
        buf_counter=0;
        state_store = true;             

        buf = aux::trim_strict(std::string(sbuf));
        sbuf[0]=0;              

        if (buf.empty()) continue;
        else return buf;
    }

    sbuf[buf_counter]=0;
    buf = aux::trim_strict(std::string(sbuf));

    return buf; 
}

int Config::convertToFpv (std::string confdir, std::string src_file, EnumNsFileType type, std::vector <std::string> &fpv)
{
    std::string option, value1, value2;
    bool running_class = false;    
    bool loop_macro_collect = false;
    bool loop_macro_serve = false;
    unsigned int loop_macro_pos = 0;
    unsigned int fwmark;
    std::vector <std::string> loop_macro;
    std::string loop_macro_header = "";
    std::ifstream ifd;
    std::string buf;

    if ((type != CONFTYPE) && (type != CLASSTYPE)) return -1;

    if (src_file.substr(0, 1) != "/") src_file = confdir + "/" + src_file; 

    ifd.open(src_file.c_str());
    if (!ifd) {
        if (type == CONFTYPE) log->error(46, src_file);
        if (type == CLASSTYPE) log->error(47, src_file);
        return -1;
    }

    while (true)
    {
        if (loop_macro_serve) {
            if (loop_macro_pos == loop_macro.size()) {
                loop_macro_serve = false;
                continue;
            }
            buf = loop_macro.at(loop_macro_pos);
            loop_macro_pos++;
        }
        else {
            buf = getLine(ifd);
            if (buf.empty()) break;
        }

        option = aux::awk(buf, 1);
        value1 = aux::awk(buf, 2);
        value2 = aux::awk(buf, 3);

        if ((option == "{sequence") || (option == "{foreach-elem") || (option == "{foreach-pair")) {
            if (type != CLASSTYPE) { log->error(851); return -1; }
            if (loop_macro_collect) { log->error(853); return -1; }
            loop_macro.clear();
            loop_macro_header = aux::trim_strict(buf);
            loop_macro_collect = true;
            continue;
        }
        else if (option == "{/}") {
            if (!loop_macro_collect) { log->error(850); return -1; }
            if (proceedLoopMacro(loop_macro_header, loop_macro) == -1) { log->error(854); return -1; }
            loop_macro_collect = false;
            loop_macro_serve = true;
            loop_macro_pos = 0;
            continue;
        }
        else if (loop_macro_collect) {
            loop_macro.push_back(buf);
            continue;
        }

        // Firstly proceed including
        if (option == "include") {
            if (loop_macro_collect) { ifd.close(); log->error(852); return -1; }
            if (includeToFpv(confdir, buf, type, fpv) == -1) { ifd.close(); return -1; }
            continue;
        }

        // Secondly proceed directives, depending on config type (main config or classes config)
        if (type == CONFTYPE) {
            if (directiveSplit(buf, fpv) == -1) { ifd.close(); return -1; }
        }
        else if (type == CLASSTYPE) {
            if ((option == "class") || (option == "class-virtual")) {
                if (!aux::awk(buf, 4).size() || aux::awk(buf, 5).size()) { log->error (24, buf); return -1; }
                if (aux::is_in_vector(RunningSections, value1)) running_class = true;
                else running_class=false;
            }
            else if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
                if (!aux::awk(buf, 3).size() || aux::awk(buf, 4).size()) { log->error (24, buf); return -1; }
                running_class = true;
            }

            if (running_class || (option == "host")) {
                if (directiveSplit (buf, fpv) == -1) { ifd.close(); return -1; }
                if (option == "host") running_class = false;
            }
            else if (option == "user") {
                log->error (104, buf);
                return -1;
            }
        }

        // protected fwmarks values
        if ((type == CLASSTYPE) && (running_class)) {
            if (option == "match") {
                if (aux::value_of_param(buf, "set-mark").size()) { log->error(860, buf); return -1; } // DEPRECATED
                if (aux::value_of_param(buf, "mark").size()) {
                    fwmark = aux::str_fwmark_to_uint(aux::value_of_param(buf, "mark"));
                    if (!aux::is_in_vector (FWMarksProtectedPartly, fwmark)) FWMarksProtectedPartly.push_back(fwmark);
                }
            }
            else if (option == "set-mark") {
                fwmark = aux::str_fwmark_to_uint(value1);
                if (aux::is_in_vector (FWMarksProtectedFully, fwmark)) { log->error(862, buf); return -1; }
                FWMarksProtectedFully.push_back(fwmark);
                FWMarksProtectedPartly.push_back(fwmark);
            }
        }
    }

    ifd.close();

    for (unsigned int n=0; n<fpv.size(); n++) fpv.at(n) = aux::trim_strict(fpv.at(n));

    return 0;
}


int Config::removeConfTypeGarbage (std::vector <std::string> &fpv)
{
    std::vector <std::string>::iterator fpvi, fpvi_begin, fpvi_end;
    std::vector <std::string> fpv_src = fpv;

    fpv.clear();

    if (aux::fpv_section_i(fpvi_begin, fpvi_end, fpv_src, "global" ) == -1 ) return -1;

    fpv.push_back("<global>");

    fpvi = fpvi_begin;
    while (fpvi <= fpvi_end) {
        fpv.push_back(*fpvi);
        fpvi++;
    }

    for (unsigned int n=0; n<RunningSections.size(); n++)
    {
        if (aux::fpv_section_i(fpvi_begin, fpvi_end, fpv_src, RunningSections.at(n)) == -1 ) return -1;

        fpv.push_back('<'+RunningSections.at(n)+'>');
        fpvi = fpvi_begin;
        while (fpvi <= fpvi_end) {
            fpv.push_back(*fpvi);
            fpvi++;
        }
    }

    return 0; 
}

int Config::addIDs (std::vector <std::string> &fpv)
{
    unsigned int classid = FIRST_CLASS_ID;
    unsigned int filterid;
    unsigned int class_fwmark; 
    bool class_set_mark_occured;
    bool filterid_early_generated;
    bool filtertest_needs_fw;
    std::string buf, option, value1;
    std::string auxbuf, auxoption, auxvalue1;
    std::string class_dev;
    std::vector <unsigned int> fwmarks_protected_partly (FWMarksProtectedPartly);
    unsigned int pos;

    filterid = 0;
    class_fwmark = 0;

    for (unsigned int n=0; n < fpv.size(); n++)
    {
        buf = fpv.at(n);
        option = aux::awk(buf, 1);

        if (aux::is_in_vector(config->ProperClassesTypes, option)) {
            if ((option == "class") || (option == "class-virtual")) {
                if (aux::awk(buf, 4).size() > MAX_CLASS_NAME_SIZE) { log->error(55, buf); return -1; }
                class_dev = aux::trim_dev(aux::awk(buf, 3));
            }
            if ((option == "class-wrapper") || (option == "class-do-not-shape")) {
                if (aux::awk(buf, 3).size() > MAX_CLASS_NAME_SIZE) { log->error(55, buf); return -1; }
                class_dev = aux::trim_dev(aux::awk(buf, 2));
            }
            class_set_mark_occured = false;
            // Generate _classid_
            classid++;
            if ((classid-FIRST_CLASS_ID) >= MAX_CLASSES_COUNT) { log->error(813, aux::int_to_str(MAX_CLASSES_COUNT)); return -1; }
            fpv.insert(fpv.begin()+n+1, ("_classid_ " + aux::int_to_str(classid)));
            n++;
            // Generate _filterid_
            filterid++;
            while (aux::is_in_vector(fwmarks_protected_partly, filterid)) filterid++;
            filterid_early_generated = true;
            // Copy first _filterid_ in class to _set-mark_ if set-mark is not found
            for (unsigned int m=n; m < fpv.size(); m++)
            {
                auxbuf = fpv.at(m);
                auxoption = aux::awk(auxbuf, 1);
                auxvalue1 = aux::awk(auxbuf, 2);

                if (auxoption == "set-mark")  {
                    class_fwmark = aux::str_fwmark_to_uint(auxvalue1);
                    fpv.erase(fpv.begin()+m);
                    m=fpv.size();
                    class_set_mark_occured = true;
                }
                else if ((auxoption == "class") || (m == (fpv.size()-1))) {
                    class_fwmark = filterid;
                    fwmarks_protected_partly.push_back(filterid);
                    m=fpv.size();
                }
            }
        }
        else if (option == "match")
        {
            if (aux::value_of_param(buf, "_filterid_").size()) { log->error(858, buf); return -1; }
            if (aux::value_of_param(buf, "_set-mark_").size()) { log->error(858, buf); return -1; }

            // Assign filterid
            if (filterid_early_generated) { 
                filterid_early_generated = false; 
            } 
            else {
                filterid++;
                while (aux::is_in_vector(fwmarks_protected_partly, filterid)) filterid++;
                fwmarks_protected_partly.push_back(filterid);
            }

            // Check for fw filter requirements
            pos = 2;
            filtertest_needs_fw = false;
            do {
                value1 = aux::awk(buf, pos);
                pos += 2;
                if (aux::is_in_vector(FilterTestsNeedFW, value1)) {
                    filtertest_needs_fw = true;
                    break;
                }
            } while (aux::awk(buf, pos).size());

            if (ifaces->tcFilterType(class_dev) != FW) {
                if (class_set_mark_occured) { 
                    log->error(811, buf + " set-mark " + aux::int_to_str(class_fwmark) + " (" + class_dev + ")");
                    return -1;
                }
                if (filtertest_needs_fw) {
                    log->error(812, buf + " (" + class_dev + ")");
                    return -1;
                }
            }

            fpv.at(n) += " _filterid_ " + aux::int_to_str(filterid);
            if (ifaces->tcFilterType(class_dev) == FW) fpv.at(n) += " _set-mark_ " + aux::int_to_str(class_fwmark);
        }
        else if (option == "_classid_") {
            log->error(858, buf);
            return -1;
        }
    }

    return 0;
}

int Config::reOrder (std::vector <std::string> &fpv)
{
    std::string buf, option;
    std::string auxbuf, auxoption;
    std::string tmp;
    unsigned int desired_position = 0;

    for (unsigned int n=0; n < fpv.size(); n++)
    {
        buf = fpv.at(n);
        option = aux::awk(buf, 1);

        // matches must be placed directly after class header
        if (aux::is_in_vector(ProperClassesTypes, option)) {
            //n++;
            desired_position = n+1;
            for (unsigned int m=n+1; m < fpv.size(); m++)
            {
                auxbuf = fpv.at(m);
                auxoption = aux::awk(auxbuf, 1);

                if (auxoption == "match") {
                    if (m==desired_position) { 
                        desired_position++; 
                        continue; 
                    }
                    tmp=fpv.at(desired_position);
                    fpv.at(desired_position)=fpv.at(m);
                    fpv.at(m)=tmp;
                    desired_position++;
                    n=desired_position;
                }
                // stop on next class or end of classfile
                else if ((aux::is_in_vector(ProperClassesTypes, auxoption)) || (m == (fpv.size()-1))) {
                    n=desired_position;
                    m=fpv.size();
                }
            }
        }
    }

    return 0;
}
 
int Config::proceedLoopMacro(std::string macro_header, std::vector <std::string> &macro_content)
{
    std::vector <std::string> macro_src;
    std::vector <std::string> macro_keys;
    std::vector <std::string> macro_values;
    std::string macro_type;
    std::string buf;

    macro_src = macro_content;
    macro_content.clear();

    if ((macro_header.substr(0, 1) != "{") || (macro_header.substr(macro_header.size()-1, 1) != "}")) { log->error (850, macro_header); return -1; }

    macro_header.erase(0, 1);
    macro_header.erase(macro_header.size()-1, 1);    

    if ((macro_type = aux::awk(macro_header, 1)).empty()) { log->error (850, macro_header); return -1; }
    if ((macro_type != "sequence") && (macro_type != "foreach-elem") && (macro_type != "foreach-pair")) { log->error (856, macro_header); return -1; }

    if (macro_type == "sequence") {
        if ((aux::awk(macro_header, 2)).empty() || (aux::awk(macro_header, 3)).empty() || (aux::awk(macro_header, 4)).size()) { log->error (857, macro_header); return -1; }
        unsigned int value1 = aux::str_to_uint(aux::awk(macro_header, 2));
        unsigned int value2 = aux::str_to_uint(aux::awk(macro_header, 3));
        if ((value1 > value2) || (value1 > MAX_MACRO_SEQ) || (value2 > MAX_MACRO_SEQ)) { log->error (855, macro_header); return -1; }
        for (unsigned int n=value1; n<=value2; n++) {
            macro_values.push_back(aux::int_to_str(n));
        }
    }

    if (macro_type == "foreach-elem") {
        unsigned int n = 2;
        if ((aux::awk(macro_header, 2)).empty()) { log->error (857, macro_header); return -1; }
        while ((aux::awk(macro_header, n)).size()) {
            macro_values.push_back(aux::awk(macro_header, n));
            n++;
        }
    }

    if (macro_type == "foreach-pair") {
        size_t cpos1 = macro_type.size();
        size_t cpos2 = macro_header.find_first_of(",");
        bool break_after_iteration = false;
        bool break_condition = false;

        if (cpos2 == std::string::npos) {
            cpos2 = macro_header.size()-1;
            break_after_iteration = true;
        } 
        else {
            cpos2--;
        }

        do {
            std::string key_and_value = macro_header.substr(cpos1, cpos2-cpos1+1);
            if ((aux::awk(key_and_value, 1)).empty() || (aux::awk(key_and_value, 2)).empty() || (aux::awk(key_and_value, 3)).size()) { log->error (857, macro_header); return -1; }
            macro_keys.push_back(aux::awk(key_and_value, 1));
            macro_values.push_back(aux::awk(key_and_value, 2));
            
            if (break_after_iteration) {
                break_condition = true;
            }
            else if (macro_header.find_first_of(",", cpos2+2) != std::string::npos) {
                cpos1 = cpos2 + 2;
                cpos2 = macro_header.find_first_of(",", cpos1)-1;
            }
            else {
                cpos1 = cpos2 + 2;
                cpos2 = macro_header.size()-1;
                break_after_iteration = true;
            }
        } while (!break_condition);
    }

    for (unsigned int n=0; n<macro_values.size(); n++) {
        for (unsigned int m=0; m<macro_src.size(); m++) {
            buf = macro_src.at(m);
            if (macro_type == "foreach-pair") {
                while (buf.find_first_of("%") != std::string::npos) {
                    buf.replace(buf.find_first_of("%"), 1, macro_keys.at(n));
                }
            }
            while (buf.find_first_of("$") != std::string::npos) {
                buf.replace(buf.find_first_of("$"), 1, macro_values.at(n));
            }
            macro_content.push_back(buf);
       }
    }

    return 0;
}

int Config::includeToFpv (std::string confdir, std::string src, EnumNsFileType type, std::vector <std::string> &fpv)
{
    std::string param, value;
    std::string include_type = "";
    std::string include_file = "";
    unsigned int n=1;

    while (aux::awk(src, ++n).size()) {
        param = aux::awk( src, n );
        value = aux::awk( src, ++n );
        if (param.empty() || value.empty()) { log->error( 24, src ); return -1; }
        
        if (param == "file") {
            include_type = param;
            include_file = value;
        }
        else { 
            log->error(24, src);
            return -1;
        }
    }

    if (include_type == "file") {
        if (convertToFpv(confdir, include_file, type, fpv) == -1) { return -1; }
    }
    else {
        log->error(24, src);
        return -1;
    }

    return 1;
}

int Config::directiveSplit (std::string arg, std::vector < std::string > &fpv)
{
    std::string option, param, value;
    std::string host_header, host_section, host_iface, host_ip, host_name;
    unsigned int host_elems;
    unsigned int pos = 0;

    // type1 directives. 
    // has 1 required value and nothing else, 
    static char t1_src[10][MAX_SHORT_BUF_SIZE] = { "ceil", "hold", "lang", "low", "mode", "rate", "reload", "set-mark", "strict" };
    std::vector <std::string> t1 (t1_src, t1_src + sizeof(t1_src)/sizeof(t1_src[0]));

    // type2 directives.
    // gets all given values as his own. Need at least 1 value.
    static char t2_src[5][MAX_SHORT_BUF_SIZE] = { "debug", "mark-on-ifaces", "local-subnets", "run", "fallback" };
    std::vector <std::string> t2 (t2_src, t2_src + sizeof(t2_src)/sizeof(t2_src[0]));

    // type4 directives
    // by iteration, gets pairs of words ( parameter and value ), 
    // it's syntax error if parameter is unknown or one of pair elements is empty.
    static char t4_src[14][17][MAX_SHORT_BUF_SIZE] = {{ "log", "file", "syslog", "terminal" },
        { "users", "replace-classes", "download-section", "upload-section", "iface-inet", "resolve-hostname" },
        { "status", "unit", "classes", "sum", "listen", "password", "do-not-shape", "file", "owner", "group", "mode", "rewrite", "file-owner", "file-group", "file-mode", "file-rewrite" },
        { "stats",  "unit", "classes", "sum", "listen", "password", "do-not-shape", "file", "owner", "group", "mode", "rewrite", "file-owner", "file-group", "file-mode", "file-rewrite" },
        { "listen", "address", "password" },
        { "section", "shape", "speed", "htb-burst", "htb-cburst" },
        { "htb", "scheduler", "prio", "burst", "cburst" },
        { "sfq", "perturb" },
        { "esfq", "hash", "perturb" },
        { "iptables", "download-hook", "upload-hook", "target", "imq-autoredirect" },
        { "imq", "autoredirect" },
        { "alter", "low", "ceil", "rate", "time-period" },
        { "quota", "low", "ceil", "rate", "day", "week", "month", "file", "reset-hour", "reset-wday", "reset-mday" },
        { "auto-hosts" }};
    static char t4iface_src[5][MAX_SHORT_BUF_SIZE] = { "speed", "do-not-shape-method", "unclassified-method", "fallback-rate", "mode" };
    std::vector <std::string> t4;
    for (unsigned int i=0; i<(sizeof(t4_src)/sizeof(t4_src[0])); i++) {
        if (std::string(std::string(t4_src[i][0])).size()) t4.push_back(std::string(t4_src[i][0]));
        else break;
    }

    // type5 directives
    // special directives, copy whole line without changes.             
    static char t5_src[6][MAX_SHORT_BUF_SIZE] = { "class", "class-virtual", "class-wrapper", "class-do-not-shape", "match", "include" };
    std::vector <std::string> t5 (t5_src, t5_src + sizeof(t5_src)/sizeof(t5_src[0]));
    
    // type6host directive.
    // special directive, some kind of macro.
    static char t6host_src[1][MAX_SHORT_BUF_SIZE] = { "host" };
    std::vector <std::string> t6host (t6host_src, t6host_src + sizeof(t6host_src)/sizeof(t6host_src[0]));

    pos = 1;
    if (aux::awk(arg, pos) == "default") pos++;
    option = aux::awk(arg, pos);

    for (unsigned int i=0; i<t1.size(); i++) {
        if (option == t1.at(i)) {
            value = aux::awk(arg, ++pos);
            if (!value.size() || aux::awk(arg, pos+1).size()) {
                log->error(24, arg);
                return -1;
            }
            
            fpv.push_back (option + " " + value);

            return 1;
        }
    }

    for (unsigned int i=0; i<t2.size(); i++) {
        if (option == t2.at(i)) {
            if (aux::awk(arg, pos+1).empty()) {
                log->error(24, arg);
                return -1;
            }            

            while (aux::awk(arg, ++pos).size()) {
                fpv.push_back(option + " " + aux::awk(arg, pos));
            }

            return 1;
        }
    }

    for (unsigned int i=0; i<=t4.size(); i++) {
        if (i == t4.size()) {
            if ((aux::awk(option, "-", 1) != "iface") || (aux::awk(option, "-", 2).empty())) break;
            if (!ifaces->isValidSysDev(aux::trim_dev(option.substr(option.find("-")+1, std::string::npos)))) { log->error(16, arg); return -1; }
        } 
        if ((i == t4.size()) || (option == t4.at(i))) {
            if (i==t4.size()) t4.assign(t4iface_src, t4iface_src + sizeof(t4iface_src)/sizeof(t4iface_src[0]));
            else t4.assign(t4_src[i]+1, t4_src[i]+sizeof(t4_src[i])/sizeof(t4_src[i][0]));

            do {
                param = aux::awk(arg, ++pos);
                value = aux::awk(arg, ++pos);
                if (param.empty() || value.empty()) {
                    log->error(24, arg);
                    return -1;
                }
                if (!aux::is_in_vector(t4, param) && (option != "auto-hosts")) {
                    log->error(11, arg);
                    return -1;
                }
                fpv.push_back (option + " " + param + " " + value);
            } while (aux::awk(arg, pos+1).size());
            return 1;
        }
    }

    for (unsigned int i=0; i<t5.size(); i++) {
        if (option == t5.at(i)) {
            fpv.push_back(arg);

            return 1;
        }
    }

    for (unsigned int n=0; n<t6host.size(); n++) {
        if (option == t6host.at(n)) {
            host_header = arg;
            host_elems = aux::awk_size(host_header);
            host_ip = aux::awk(host_header, host_elems-1);
            host_name = aux::awk(host_header, host_elems);
            if (!test->validIp(host_ip)) { log->error(29, arg); return -1; }   
            // Auto Host
            if (host_elems == 3) {
                if (aux::awk_size(AutoHostsBasis) == 0) { log->error(815, arg); return -1; }
                host_header = "host " + AutoHostsBasis + " " + host_ip + " " + host_name;
                host_elems = aux::awk_size(host_header);
            }

            if ((host_elems < 5) || ((host_elems-3)%2)) { 
                log->error(24, arg);
                return -1;
            }   

            for (unsigned int m=2; m<=(host_elems-3); m++) {
                host_section = aux::awk(host_header, m);
                host_iface = aux::awk(host_header, ++m);
                if (!aux::is_in_vector(RunningSections, host_section)) continue;
                if (!ifaces->isValidSysDev(host_iface)) { log->error(16, host_header); return -1; }   
                fpv.push_back( "class " + host_section + " " + host_iface + " " + host_name);
                fpv.push_back(" match _auto-srcip-dstip_ " + host_ip);
            }

            return 1;
        }
    }

    // Check for section tag
    option = aux::awk(arg, 1);
    if (aux::awk(arg, 2).size()) {
        log->error(24, arg);
        return -1;
    }

    if ((option.at(0) == '<') && (option.at(option.size()-1) == '>')) 
    {
        fpv.push_back( arg );
        return 1;   
    }

    // Directive not found
    log->error ( 11, arg );
    return -1;
}

int Config::setListenerAddress (std::string arg)
{
    std::string ip_addr = "";
    int ip_port = 0;

    if (aux::split_ip_port (arg, ip_addr, ip_port) == -1) return -1;

    ListenerIp = ip_addr;
    if (ip_port) ListenerPort = ip_port;

    return 0;
}

int Config::addLocalSubnet (std::string local_subnet)
{
    std::string addr, mask;

    if (aux::split_ip(local_subnet, addr, mask) == -1 ) return -1;
    
    LocalSubnets.push_back(std::string(addr) + "/" + std::string(mask));

    return 0;
}

int Config::addAutoHostsBasis (std::string section, std::string iface)
{
    if (!AutoHostsBasis.empty()) AutoHostsBasis += " ";

    AutoHostsBasis += (section + " " + iface);

    return 0;
}

