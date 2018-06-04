/*
 *      NiceShaper - Dynamic Traffic Management
 *
 *      Copyright (C) 2004-2016 Mariusz Jedwabny <mariusz@jedwabny.net>
 *
 *      This file is subject to the terms and conditions of the GNU General Public
 *      License.  See the file COPYING in the main directory of this archive for
 *      more details.
 */

#include "aux.h"

#include <netdb.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <string>
#include <vector>
#include <iostream>
#include <sstream>

#include "main.h"
#include "logger.h"
#include "ifaces.h"
#include "tests.h"

// Cut off new lines(Linux LF and Windows CR+LF), tabs and spaces from beginning and end of string
// When strict is true, remove all not permitted chars from whole string
std::string aux::trim(std::string source, bool strict)
{
    std::string chars_bad = "\t\n\r";
    std::string chars_strict = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_:*<>,./{}$%";
    size_t pos;

    if (source.empty()) return "";

    if (strict) pos = source.find_last_of(chars_strict);
    else pos = source.find_last_not_of(chars_bad+" ");

    if (pos == std::string::npos) return "";
    else if (pos != (source.size()-1)) source.erase(pos+1);

    if (strict) pos = source.find_first_of(chars_strict);
    else pos = source.find_first_not_of(chars_bad+" ");

    if (pos == std::string::npos) return "";
    else if (pos) source.erase(0, pos);

    if (!strict || source.empty()) return source;

    while ((pos = source.find_first_not_of(chars_strict+" ")) != std::string::npos) {
        source.replace(pos, 1, " ");
    }

    pos = 0;
    while ((pos+1) < source.size()) {
        if ((source.at(pos) == 32) && (source.at(pos+1) == 32)) source.erase(pos+1, 1);
        else pos++;
    }

    return source;
}

std::string aux::trim_legacy(std::string source)
{
    return trim (source, false);   
}

std::string aux::trim_strict(std::string source)
{
    return trim (source, true);
}

std::string aux::awk(std::string source, unsigned int position)
{
    std::string result = "", word = "";
    std::stringstream srcstream(source);
    unsigned int n = 0;
    
    while (srcstream >> word) 
    {
        n++;
        if (n == position) {
            result = word;
            return result;
        }
    }

    return result;                                                                    
} 

std::string aux::awk(std::string source, std::string separator, unsigned int position)
{
    std::string buf;
    
    buf = source;
    while (buf.find(separator) != std::string::npos) {
        buf.replace(buf.find(separator), 1, " ");
    }
                        
    return awk(buf, position);
} 

unsigned int aux::awk_size(std::string source)
{
    unsigned int n = 1;

    while (awk(source, n).size()) n++;
    n--;

    return n;
}

int aux::power( int val , int inc )
{
    int result = 1;

    for ( int n = 1; n <= inc ; n++ ) result = result * val;

    return result;
}

unsigned int aux::compute_quantum ( unsigned int rate )
{
    unsigned int quantum=rate/8/1500;

    if (!quantum) quantum=1;

    return quantum;
}

std::string aux::int_to_str(int arg)
{
    std::stringstream srcstream;
    std::string result;
    
    srcstream << arg;
    srcstream >> result;
    
    return result;
}

std::string aux::int_to_str(unsigned int arg)
{
    std::stringstream srcstream;
    std::string result;
    
    srcstream << arg;
    srcstream >> result;
    
    return result;
}

std::string aux::int_to_str(int arg, unsigned int pad) 
{
    std::string buf = int_to_str(arg);
    
    if ((pad-buf.size()) <= 0) return buf;

    buf.insert(0, pad-buf.size(), '0');
    
    return buf;
}

std::string aux::int_to_hex(int arg)    
{
    std::stringstream srcstream;
    std::string result;
                            
    srcstream << std::hex << arg;
    srcstream >> result;

    return result;
}

unsigned int aux::str_to_uint(std::string arg)
{
    std::stringstream srcstream;
    unsigned int result;
    
    srcstream << arg;
    srcstream >> result;
    
    return result;
}

int aux::str_to_int(std::string arg)
{
    std::stringstream srcstream;
    int result;
    
    srcstream << arg;
    srcstream >> result;
    
    return result;
}

double aux::str_to_double(std::string arg)
{
    std::stringstream srcstream;
    double result;
    
    srcstream << arg;
    srcstream >> result;
    
    return result;
}
 
__u64 aux::str_to_u64(std::string arg)
{
    std::stringstream srcstream;
    __u64 result;
    
    srcstream << arg;
    srcstream >> result;
    
    return result;
}

unsigned int aux::str_fwmark_to_uint(std::string arg)
{
    int base;

    if ( (arg.at(0) == '0') &&  (arg.at(1) == 'x')) base=16;
    else base=10;

    return strtoul(arg.c_str(),NULL,base);
}

bool aux::is_uint (std::string arg)
{
    if (arg.empty()) return false;

    if (arg.find_first_not_of("0123456789") == std::string::npos) return true;

    return false;
}

void aux::shift (unsigned int &var1, unsigned int &var2)
{
    unsigned int tmp = var1;

    var1 = var2;
    var2 = tmp;
}

std::string aux::trim_dev (std::string dev)
{
    dev = trim_strict(dev);

    if (dev.find_first_of(":") != std::string::npos) {
        log->warning (11, dev);
        dev.erase(dev.find_first_of(":"));
    }

    return dev;
} 

int aux::dot_to_bit(std::string mask)
{
    unsigned long addr;
    int n, bit;

    addr=ntohl( inet_addr(mask.c_str()));
    for ( n=0, bit=0; n<32; n++ ) bit += (addr>>n)&1;

    return bit;
}

std::string aux::bit_to_dot(int arg)
{
    struct in_addr netwrk;
    int n, m;

    if (arg < 0 || arg > 32) return "255.255.255.255";
    for (m = 0, n = 0; n < arg; n++) m += 1 << (31 - n);
    netwrk.s_addr = htonl(m);

    return std::string(inet_ntoa(netwrk));
}

std::string aux::ip_to_hostname(std::string ipaddr)
{
    uint32_t addr;
    struct hostent *hp;
      
    addr = inet_addr(ipaddr.c_str());
    hp = gethostbyaddr( (char *) &addr, sizeof(addr), AF_INET );

    if ( hp==NULL ) return std::string(ipaddr);
    else return std::string(hp->h_name);
}

int aux::split_ip(const std::string src, std::string &ipaddr, std::string &ipmask)
{
    ipaddr = "";
    ipmask = "";
    
    if (awk(src, 1).empty() || awk(src, 2).size()) { log->error( 29, src); return -1; }

    if ((src.find("/") != std::string::npos) && (awk(src, "/", 1).empty() || awk(src, "/", 2).empty() ||  awk(src, "/", 3).size())) { log->error( 29, src ); return -1; }

    if (src.find("/") != std::string::npos ) {
        ipaddr = trim_strict(awk(src, "/", 1));
        ipmask = trim_strict(awk(src, "/", 2));
    } 
    else {
        ipaddr = trim_strict(src);
        ipmask = "255.255.255.255";
    }

    if (!test->validIp(ipaddr)) { log->error(29, src); return -1; }

    if (!test->validIp(ipmask)) {
        if (str_to_uint(ipmask)<=32) ipmask = bit_to_dot(str_to_int(ipmask));
        else { log->error(50, src); return -1; }
    }
    
    return 1;
}

int aux::split_ip_port (std::string arg, std::string &ip_addr, int &ip_port)
{
    ip_addr = "";
    ip_port = 0;
    
    if (awk(arg, 1).empty() || awk(arg, 2).size()) { log->error( 29, arg ); return -1; }

    if ((arg.find(":") != std::string::npos) && (awk(arg, ":", 1).empty() || awk(arg, ":", 2).empty() ||  awk(arg, ":", 3).size())) { log->error( 29, arg ); return -1; }

    if (arg.find(":") != std::string::npos) {
        ip_addr = trim_strict(awk(arg, ":", 1));
        ip_port = str_to_int(trim_strict(awk(arg, ":", 2)));
        if (int_to_str(ip_port) != trim_strict(awk(arg, ":", 2))) { log->error( 50, arg ); return -1; }
        if ((ip_port < 1) || (ip_port > 65536)) { log->error( 50, arg ); return -1; }
    } 
    else {
        ip_addr = trim_strict(arg);
        ip_port = 0;
    }

    if (!test->validIp (ip_addr)) { log->error( 29, arg ); return -1; }
        
    return 1;
}

int aux::fpv_section_i (std::vector <std::string>::iterator &fpvi_begin, std::vector <std::string>::iterator &fpvi_end, std::vector <std::string> &fpv, std::string section)
{
    std::vector <std::string>::iterator fpvi;

    // locate start of section
    fpvi = fpv.begin();  
    while (fpvi != fpv.end()) {
        if (*fpvi == ("<" + section + ">")) {
            fpvi_begin = ++fpvi; 
            break; 
        }
        fpvi++;
    }

    // end of config file, section start not found or section without directives
    if (fpvi == fpv.end()) {
        log->error( 39, section ); 
        return -1;
    }   

    // locate end of section
    fpvi_end = fpvi_begin;
    while (fpvi != fpv.end()) {
        // section end in format: </name>
        if (*fpvi == ("</" + section + ">")) break;
        // section end in format: </>
        else if (*fpvi == "</>") break; 
        // another section start tag
        else if ((awk(*fpvi, 1).size()) && (awk(*fpvi, 2).empty()) && ((*fpvi).at(0) == '<') && ((*fpvi).at((*fpvi).size()-1) == '>')) break;
        fpvi_end = fpvi;
        fpvi++;
    }

    if (fpvi_begin == fpvi_end) {
        log->error(39, section); 
        return -1;
    }

    return 1;
}

std::string aux::value_of_param (std::string source, std::string param)
{
    unsigned int n=1;

    while (awk(source, n).size()) {
        if ( awk(source, n) == param) {
            if (awk(source, ++n).size()) {
                return awk(source, n);
            } 
            else {
                return "";
            }
        }
        n++;
    }

    return "";
}

EnumUnits aux::get_unit(std::string arg)
{
    size_t pos=0;
    std::string unit;
    
    for (pos=0; pos<arg.size(); pos++)
    {
        if ((arg.substr(pos, 1)).find_first_of("0123456789") == std::string::npos ) {
            break;
        }
    }
    unit = arg.substr(pos, std::string::npos);
    
    // Bits    
    if ((unit == "b/s") || (unit == "b")) return BITS;
    else if ((unit == "kb/s") || (unit == "Kb/s") || (unit == "kb") || (unit == "Kb")) return KBITS;
    else if ((unit == "mb/s") || (unit == "Mb/s") || (unit == "mb") || (unit == "Mb")) return MBITS;

    // Bytes
    else if ((unit == "B/s") || (unit == "B")) return BYTES;
    else if ((unit == "kB/s") || (unit == "KB/s") || (unit == "kB") || (unit == "KB")) return KBYTES;
    else if ((unit == "mB/s") || (unit == "MB/s") || (unit == "mB") || (unit == "MB")) return MBYTES;

    else if (unit.empty()) return BITS;
 
    else {
        log->warning(12, arg);
        return BITS;
    }   
}

std::string aux::unit_to_str(EnumUnits arg, bool without_ps)
{
    if (arg == BITS) return "b/s";
    else if (arg == KBITS) return "kb/s";
    else if (arg == MBITS) return "Mb/s";
    else if ((arg == BYTES) && (without_ps)) return "B";
    else if ((arg == KBYTES) && (without_ps)) return "kB";
    else if ((arg == MBYTES) && (without_ps)) return "MB";
    else if (arg == BYTES) return "B/s";
    else if (arg == KBYTES)  return "kB/s";
    else if (arg == MBYTES) return "MB/s";
    else return "";
}

unsigned int aux::unit_convert(std::string arg, EnumUnits resunit)
{
    return (str_to_uint(arg) * (unsigned int)get_unit(arg) / (unsigned int)resunit);
}

unsigned int aux::unit_convert(unsigned int arg, EnumUnits resunit)
{
    return (arg / (unsigned int)resunit);
}

bool aux::is_in_vector (std::vector <std::string> &fpv, std::string arg)
{
    std::vector <std::string>::iterator fpvi;

    fpvi = fpv.begin();  
    while ( fpvi != fpv.end()) {
        if ( *fpvi == arg ) return true;
        fpvi++;
    }

    return false;
}

bool aux::is_in_vector (std::vector <unsigned int> &fpv, unsigned int arg)
{
    std::vector <unsigned int>::iterator fpvi;

    fpvi = fpv.begin();  
    while ( fpvi != fpv.end()) {
        if ( *fpvi == arg ) return true;
        fpvi++;
    }

    return false;
}


