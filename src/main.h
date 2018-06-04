#ifndef MAIN_H
#define MAIN_H

#include <linux/types.h>

#include <string>
#include <vector>

const std::string VERSION("1.2.4"); 

const unsigned int MAX_LONG_BUF_SIZE = 1024;
const unsigned int MAX_SHORT_BUF_SIZE = 64;
const unsigned int MAX_CLASS_NAME_SIZE = 20;
const unsigned int MAX_SECTION_NAME_SIZE = 15;
const unsigned int MAX_RATE = 1000000000;
const unsigned int MIN_RATE = 8;
const unsigned int MAX_CONTROLLER_HANDLERS = 2;
const unsigned int FIRST_SECTION_ID = 0x10;
const unsigned int FIRST_WAITINGROOM_ID = 0x100;
const unsigned int FIRST_CLASS_ID = 0x1000;
const unsigned int MAX_SECTIONS_COUNT = FIRST_WAITINGROOM_ID - FIRST_SECTION_ID - 0x2;
const unsigned int MAX_CLASSES_COUNT = 0xEFFF - FIRST_CLASS_ID;
const unsigned int MAX_MACRO_SEQ = 65535;
 
enum EnumNsFileType { CONFTYPE, CLASSTYPE };
enum EnumUnits { BITS = 1, KBITS = 1000, MBITS = 1000000, BYTES = 8, KBYTES = 8000, MBYTES = 8000000 };
enum EnumFlowDirection { DWLOAD, UPLOAD, UNSPEC };
enum EnumNsClassType { STANDARD_CLASS, VIRTUAL, WRAPPER, DONOTSHAPE };
enum EnumTcObjectType { QOS_CLASS, QOS_QDISC, QOS_FILTER };
enum EnumTcQdiscType { HTB, NOQDISC, SFQ, ESFQ };
enum EnumTcFilterType { U32, FW  };
enum EnumTcOperation { QOS_ADD, QOS_MOD, QOS_REP, QOS_DEL };
enum EnumLang { EN, PL_UTF8 };
enum EnumStatusShowClasses { SC_ALL, SC_ACTIVE, SC_WORKING, SC_FALSE };
enum EnumStatusShowSum { SS_TOP, SS_BOTTOM, SS_FALSE };

extern std::string pidfile;
extern std::string confdir;
extern std::string conffile;
extern std::string classfile;
extern std::string vardir;
extern std::string iptfile;
extern std::string svinfofile;

extern class Config *config;
extern class IfacesMap *ifaces;
extern class Iptables *ipt;
extern class Logger *log;
extern class Sys *sys;
extern class Tests *test;

extern void sig_exit_daemonizer_ok(int);
extern void sig_exit_daemonizer_error(int);
extern void sig_exit_supervisor(int);

#endif

