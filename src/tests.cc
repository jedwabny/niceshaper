/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "tests.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>

#include <string>
#include <vector>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "main.h"
#include "aux.h"
#include "logger.h"

Tests::Tests () 
{
    gettimeofday(&TimerStart, NULL);
}

Tests::~Tests () 
{
    // nothing
}

bool Tests::validIp(std::string ipaddr)
{
    struct in_addr inaddr;
    if ( !inet_aton( ipaddr.c_str(), &inaddr )) return false;
    if ( ipaddr.c_str() != std::string(inet_ntoa( inaddr ))) return false;
    return true;
}

bool Tests::validPort(int tcpport)
{
    if (tcpport >= 1 && tcpport <= 65536) return true;
    else return false;
}

bool Tests::solidIpMask(std::string ipmask)
{
    unsigned long addr;

    if ( !validIp( ipmask )) return false;
    addr = htonl( inet_addr( ipmask.c_str()));
    for ( int n=1; n<32; n++ )
        if ((( addr>>n)&1)==0 && (( addr>>(n-1))&1)==1 ) return false;

    return true;
}

bool Tests::fileExists (std::string path)
{
    if (!access(path.c_str(), F_OK)) {
        return true;
    }

    return false;
}

bool Tests::fileIsReadable (std::string path) 
{
    if (!access(path.c_str(), R_OK)) {
        return true;   
    }

    return false;
}

bool Tests::fileIsWriteable (std::string path) 
{
    if (!access( path.c_str(), W_OK)) {
        return true;   
    }

    return false;
}

bool Tests::fileIsExecutable (std::string path) 
{
    if (!access(path.c_str(), X_OK)) {
        return true;
    }

    return false;
}
        
bool Tests::ifaceIsImq(std::string iface)
{
    if (iface.substr(0, 3) == "imq") return true;

    return false;
}

std::string Tests::whichExecutable (std::string path)
{
    std::string buf;
    char *env_lang = getenv("PATH");
    unsigned int n=1;

    if (env_lang == NULL) return "";
    buf = std::string(env_lang);

    do {
        if (fileIsExecutable(aux::awk(buf, ":", n)+"/"+path)) return (aux::awk(buf, ":", n)+"/"+path);
    } while (aux::awk(buf, ":", ++n).size());

    return "";
}

void Tests::timerReset()
{
    gettimeofday(&TimerStart, NULL);
}

void Tests::timerPrint()
{
    struct timeval timer;
    unsigned int timer_usecs;
    std::string timer_msecs;

    gettimeofday (&timer, NULL);
    timer_usecs = (timer.tv_sec-TimerStart.tv_sec)*1000000+timer.tv_usec-TimerStart.tv_usec;
    timer_msecs = aux::int_to_str((timer_usecs % 1000000) / 1000);
    if (timer_msecs.size() < 3) timer_msecs.insert(0,(3-timer_msecs.size()),'0');
    log->info (8, aux::int_to_str(timer_usecs/1000000) + "." + timer_msecs);
}

