ldfl_mapping_t ldfl_mapping[] = {
    /* name                   search_pattern          operation         target                extra_options         */
    { "temp files redirect",  ".*/temp/([^/]*)$",     LDFL_OP_MAP,      "/tmp/$1",            NULL                   },
    { "inc redirect",         "(.*)/inc/(.*)",        LDFL_OP_MAP,      "$1/lib/$2",          NULL                   },
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


ldfl_setting_t ldfl_setting = {
    .log_mask    = LDFL_LOG_MAPPING_RULE_FOUND | LDFL_LOG_FN_CALL | LDFL_LOG_INIT | LDFL_LOG_MAPPING_RULE_APPLY | LDFL_LOG_FN_CALL_ERR,
    .log_level   = LOG_DEBUG,
    .logger      = ldfl_syslog_logger,
};
