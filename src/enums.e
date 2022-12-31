OPT MODULE

->#Error Constants
EXPORT ENUM ERR_NOERROR=0,
            ERR_NOMUI=50,
            ERR_NOAPP,
            ERR_NOASL,
            ERR_NOBSD,
            ERR_NOMIAMI,
            ERR_NOICON,
            ERR_NODNSRESULT,
            ERR_NOSOCK,
            ERR_NOMEM,
            ERR_USERABORT,
            ERR_NOTIMER,
            ERR_NOLOCALE=1000

->#Signal Constants
EXPORT ENUM ID_GO=1,
            ID_LIST,
            ID_RANGE,
            ID_ABOUT,
            ID_MUIABOUT,
            ID_MUISET,
            ID_LOOKUP,
            ID_ICONIFY,
            ID_UNICONIFY,
            ID_CANCEL,
            ID_LOOKUPCYC,
            ID_PREFS,
            ID_SAVEPREF,
            ID_USEPREF,
            ID_CANCELPREF,
            ID_DOUBLECLICK,
            ID_CLOSEBOOK,
            ID_BOOKDOUBLE,
            ID_OPENLOOKUP,
            ID_OPENBOOK,
            ID_OPENFREQ,
            ID_OPENCUSTOM,
            ID_CLOSECUSTOM,
            ID_OKCUSTOM,
            ID_SCANTYPE,
            ID_PING,
            ID_RESOLVE,
            ID_REALQUIT,
            ID_TRACE,
            ID_PINGSWEEP,
            ID_WRITELOG,
            ID_UDPPING

->#Termination Constants
EXPORT ENUM TERM_NONE=0,
            TERM_NORMAL,
            TERM_USER

EXPORT ENUM OBID_HOST_TB=1,
            OBID_LOGPATH_TB,
            OBID_PORTRANGE_TB,
            OBID_TELHELP_TB,
            OBID_FTPHELP_TB,
            OBID_WEBHELP_TB,
            OBID_OTHERHELP_TB,
            OBID_SWEEPADDR_NUM,
            OBID_PING_NUM,
            OBID_DELAY_SLI,
            OBID_TRACEMAXHOPS_SLI,
            OBID_RPTIMEOUT_SLI,
            OBID_READPORTS_CHK,
            OBID_SERVICE_CHK,
            OBID_WAKEUP_CHK,
            OBID_TROJAN_CHK,
            OBID_BLOCKING_CHK,
            OBID_STEALTH_CHK,
            OBID_CLOSED_CHK,
            OBID_TRACEDNS_CHK,
            OBID_SWEEPDNS_CHK,
            OBID_SWEEPICMP_CHK,
            OBID_SCANTYPE_CYC,
            OBID_TROUTETYPE_CYC,
            OBID_SWEEPTYPE_CYC
