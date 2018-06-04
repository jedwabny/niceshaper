#ifndef TESTS_H                                                                                                                                         
#define TESTS_H  

#include <sys/time.h>

#include <string>
#include <vector>

class Tests
{
    public:
        Tests();
        ~Tests();
        bool validIp(std::string);
        bool validPort(int);
        bool solidIpMask(std::string);
        bool fileExists(std::string); 
        bool fileIsReadable(std::string); 
        bool fileIsWriteable(std::string); 
        bool fileIsExecutable(std::string);
        bool ifaceIsImq(std::string);
        std::string whichExecutable(std::string);
        void timerReset();
        void timerPrint();
    private:
        struct timeval TimerStart;
};

#endif

