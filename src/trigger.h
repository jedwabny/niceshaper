#ifndef TRIGGER_H
#define TRIGGER_H

class Trigger {
    public:
        Trigger ();
        virtual ~Trigger ();
        bool isActive () { return Active; }
        bool isUseNsLow () { return UseNsLow; }
        bool isUseNsCeil () { return UseNsCeil; }
        unsigned int &getTriggerNsLowRef() { return TriggerNsLow; }
        unsigned int &getTriggerNsCeilRef() { return TriggerNsCeil; }
        void setActive (bool active) { Active = active; } 
    protected:
        int storeReplaced (std::string);
        unsigned int TriggerNsLow;
        unsigned int TriggerNsCeil;
        bool UseNsLow;
        bool UseNsCeil;
        bool UseTrigger;
        bool Active;
    private:
};

class TriggerAlter : public Trigger {
    public:
        TriggerAlter ();
        ~TriggerAlter ();
        int store (std::string);
        int check (unsigned int);
    private:
        unsigned int TimePeriodFrom;
        unsigned int TimePeriodTo;
};

class TriggerQuota : public Trigger {
    public:
        TriggerQuota ();
        ~TriggerQuota ();
        int store (std::string);
        int totalize (unsigned int);
        int check (unsigned int, unsigned int, unsigned int, bool);
        std::string dumpCounters ();
        void setCounters (unsigned int, unsigned int, unsigned int);
    private:
        int readQuota (std::string, unsigned int &);
        unsigned int LimitDay;
        unsigned int LimitWeek;
        unsigned int LimitMonth;
        unsigned int ResetDmin;
        unsigned int ResetWday;
        unsigned int ResetMday;
        unsigned int TotalDay;
        unsigned int TotalWeek;
        unsigned int TotalMonth;
        unsigned int TotalMinor;
        bool IsDayResetted;
        bool IsWeekResetted;
        bool IsMonthResetted;
};

#endif

