#ifndef SUPERVISOR_H
#define SUPERVISOR_H

#include "main.h"

#include "worker.h"

class Supervisor {
    public:
        Supervisor();
        ~Supervisor();	
        int init();
        int entry(std::vector <std::string> &, std::vector <std::string> &);
        int loop();
    private:
        int reloadsVectorInit(); 
        int reloadsVectorInsert(unsigned int, struct timeval);
        int recoverQos();
        int recoverIpt();
        int recoverMissU32Perf();
        // Threads methods
        static void *controllerHandlerThreadEntry(void *);
        static void *statusWriterThreadEntry(void *);
        void *controllerHandler();
        void *statusWriter();
        ///
        int fillAccountingHelper();
        int prepareEnvironment(std::vector <std::string> &, std::vector <std::string> &);
        void quitAtInit();
        //
        pthread_mutex_t ThreadsExitRequestLock;
        pthread_mutex_t ControllerHandlerLock;
        pthread_mutex_t StatusFileOutOfDateLock;
        int ControllerHandlerSocket;
        bool ControllerHandlersCreated;
        bool StatusWriterCreated;
        volatile unsigned int ControllerHandlerGoHome; // As my child says "Idź do domu!" which means "Go home!" when he scares away insects and bad dogs:)
        volatile unsigned int StatusWriterGoHome;
        bool StatusFileOutOfDate;
        bool SAOContainterRequired;
        std::vector <Worker *> Workers;
        std::vector <WorkerReloadDemand *> ReloadsVector;
        std::vector <std::string> FPVConfFile;
        std::vector <std::string> FPVClassFile;
        bool Initialized;
};

#endif

