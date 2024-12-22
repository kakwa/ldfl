ldfl_mapping_t ldfl_mapping[] = {
    /* name                   search_pattern          operation         target                extra_options         */
    { "temp files redirect",  ".*/temp/\\([^/]*\\)$", LDFL_OP_MAP,      "/tmp/\\1",           NULL                   },
    { "executable redirect",  ".*/.bin/\\([^/]*\\)$", LDFL_OP_EXEC_MAP, "/opt/fliar/bin/\\1", NULL                   },
    { "memory open",          ".*/file[0-9].txt",     LDFL_OP_MEM_OPEN, NULL,                 NULL                   },
    { "static file",          ".*/static.bin",        LDFL_OP_STATIC,   ldf_default_blob,     NULL                   },
    { "change data perm",     ".*/data/.*",           LDFL_OP_PERM,     NULL,                 "kakwa:kakwa|0700|0600"},
    { "change data location", NULL,                   LDFL_OP_MAP,      NULL,                 NULL                   }, // Also applies this rule on pattern ".*/data/.*"
    { "allow /dev",           "^/dev/.*",             LDFL_OP_NOOP,     NULL,                 NULL                   },
    { "allow /proc",          "^/proc/.*",            LDFL_OP_NOOP,     NULL,                 NULL                   },
    { "allow /sys",           "^/sys/.*",             LDFL_OP_NOOP,     NULL,                 NULL                   },
    { "default & deny",       ".*",                   LDFL_OP_DENY,     NULL,                 NULL                   },
    { NULL,                   NULL,                   LDFL_OP_END,      NULL,                 NULL                   }  // keep this last value
};


/*

.log_level values:
* LOG_EMERG
* LOG_ALERT
* LOG_CRIT
* LOG_ERR
* LOG_WARNING
* LOG_NOTICE
* LOG_INFO
* LOG_DEBUG

.logger values:
* ldfl_syslog_logger
* ldfl_stderr_logger
* ldfl_dummy_logger

or any logger implementing:
void cust_logger(int priority, const char *fmt, ...) {}

Use log_mask to enable/disable some log categories:

* LDFL_LOG_INIT:            Log initialization
* LDFL_LOG_FN_CALL:         Log LibC function calls
* LDFL_LOG_MAPPING_SEARCH:  Log mapping search stuff
* LDFL_LOG_MAPPING_APPLY:   Log mapping application stuff
* LDFL_LOG_ALL:             Log everything

Compose them like so: LDFL_LOG_FN_CALL | LDFL_LOG_MAPPING_APPLY
*/

ldfl_setting_t ldfl_setting = {
    .log_mask    = LDFL_LOG_FN_CALL | LDFL_LOG_INIT,
    .log_level   = LOG_DEBUG,
    .logger      = ldfl_syslog_logger,
};
