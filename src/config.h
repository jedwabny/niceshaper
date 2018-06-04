#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>

#include "main.h"

class Config 
{
    public:
        Config ();
        ~Config ();
        int convertToFpv (std::string, std::string, EnumNsFileType, std::vector <std::string> &);
        int removeConfTypeGarbage (std::vector <std::string> &);
        int addIDs (std::vector <std::string> &);
        int reOrder (std::vector <std::string> &);
        int proceedLoopMacro(std::string, std::vector <std::string> &);
        int includeToFpv (std::string, std::string, EnumNsFileType, std::vector <std::string> &);
        EnumUnits getStatusUnit () { return StatusUnit; }
        std::string getListenerIp () { return ListenerIp; }
        int getListenerPort () { return ListenerPort; }
        std::string getListenerPassword () { return ListenerPassword; }
        std::string getStatusFilePath () { return StatusFilePath; }
        std::string getStatusFileOwner () { return StatusFileOwner; }
        std::string getStatusFileGroup () { return StatusFileGroup; }
        std::string getStatusFileMode () { return StatusFileMode; }
        int getStatusFileRewrite () { return StatusFileRewrite; }
        EnumStatusShowClasses getStatusShowClasses () { return StatusShowClasses; }
        EnumStatusShowSum getStatusShowSum () { return StatusShowSum; }
        bool getStatusShowDoNotShape () { return StatusShowDoNotShape; }
        bool getImqAutoRedirect () { return ImqAutoRedirect; }
        void addRunningSection (std::string running_section) { RunningSections.push_back(running_section); }
        void setStatusUnit (EnumUnits status_unit) { StatusUnit = status_unit; }
        int setListenerAddress (std::string);   
        void setListenerPassword (std::string listener_password) { ListenerPassword = listener_password; }
        void setStatusFilePath (std::string status_file_path) { StatusFilePath = status_file_path; }
        void setStatusFileOwner (std::string status_file_owner) { StatusFileOwner = status_file_owner; }
        void setStatusFileGroup (std::string status_file_group) { StatusFileGroup = status_file_group; }
        void setStatusFileMode (std::string status_file_mode) { StatusFileMode = status_file_mode; }
        void setStatusFileRewrite (int status_file_rewrite) { StatusFileRewrite = status_file_rewrite; } 
        void setStatusShowClasses (EnumStatusShowClasses status_show_classes) { StatusShowClasses = status_show_classes; }
        void setStatusShowSum (EnumStatusShowSum status_show_sum) { StatusShowSum = status_show_sum; }
        void setStatusShowDoNotShape (bool status_show_do_not_shape) { StatusShowDoNotShape = status_show_do_not_shape; }
        void setImqAutoRedirect (bool imq_auto_redirect) { ImqAutoRedirect = imq_auto_redirect; }
        int addLocalSubnet (std::string);
        int addAutoHostsBasis (std::string, std::string);
        unsigned int getReqRecoverWait() { return ReqRecoverWait; }
        unsigned int getStartStopDots() { return StartStopDots; }
        //
        std::vector <std::string> ProperClassesTypes;
        std::vector <std::string> FilterTestsNeedFW;
        std::vector <std::string> RunningSections;
        std::vector <std::string> LocalSubnets;
        std::string AutoHostsBasis;
    private:
        std::string getLine(std::ifstream &);
        int directiveSplit (std::string, std::vector <std::string> &); 
        std::string ListenerIp;
        int ListenerPort;
        std::string ListenerPassword;
        std::string StatusFilePath;
        std::string StatusFileOwner;
        std::string StatusFileGroup;
        std::string StatusFileMode;
        EnumUnits StatusUnit;
        EnumStatusShowClasses StatusShowClasses;
        EnumStatusShowSum StatusShowSum;
        int StatusFileRewrite;
        bool StatusShowDoNotShape;
        bool ImqAutoRedirect;
        std::vector <unsigned int> FWMarksProtectedPartly;
        std::vector <unsigned int> FWMarksProtectedFully;
        unsigned int ReqRecoverWait; 
        unsigned int StartStopDots;
};

#endif
