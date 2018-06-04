#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <iostream>

#include "main.h"

class Logger
{
    public:
        Logger (); 
        ~Logger ();
        std::string getErrorMessage(int);
        std::string getWarningMessage(int);
        std::string getInfoMessage(int);
        void error (int);
        void error (int, std::string);
        void error (std::string, int, std::string);
        void error (std::string, int);
        void warning (int);
        void warning (int, std::string);
        void warning (std::string, int, std::string);
        void warning (std::string, int);
        void info (int);
        void info (int, std::string);
        void info (std::string, int, std::string);
        void info (std::string, int);
        void dump (std::string, std::string, std::string);
        void onTerminal (std::string);
        void toSyslog (std::string);
        void toLogFile (std::string);
        void setLang (EnumLang lang) { Lang = lang; } 
        void setLogOnTerminal (bool log_on_terminal) { LogOnTerminal = log_on_terminal; }
        void setLogToSyslog (bool log_to_syslog) { LogToSyslog = log_to_syslog; }
        void setDoNotPutNewLineChar(bool do_not_put) { DoNotPutNewLineChar = do_not_put; }
        void setLogFile (std::string);
        void setErrorLogged (bool error_logged) { ErrorLogged = error_logged; }
        bool getErrorLogged () { return ErrorLogged; }
        void dumpFooter ();
        void dumpHelp ();
        //
        void setReqRecoverQos(bool req_recover_qos) { ReqRecoverQos = req_recover_qos; }
        bool getReqRecoverQos() { return ReqRecoverQos; }
        void setReqRecoverIpt(bool req_recover_ipt) { ReqRecoverIpt = req_recover_ipt; }
        bool getReqRecoverIpt() { return ReqRecoverIpt; }
        void setReqRecoverMissU32Perf(bool req_recover_miss_u32_perf) { ReqRecoverMissU32Perf = req_recover_miss_u32_perf; }
        bool getReqRecoverMissU32Perf() { return ReqRecoverMissU32Perf; }
    private:
        EnumLang Lang;
        bool ErrorLogged;
        bool LogOnTerminal;
        bool LogToSyslog;
        bool LogToFile;
        bool DoNotPutNewLineChar;
        bool MissingNewLineChar;
        std::string LogFile;
        //
        bool ReqRecoverQos;
        bool ReqRecoverIpt;
        bool ReqRecoverMissU32Perf;
};

#endif
