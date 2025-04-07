static const unsigned char ldf_default_blob[] = "hello from ld-fliar";

ldfl_mapping_t ldfl_mapping[] = {
    /* name                   search_pattern          operation         target                path_transform, extra_options         */
    { "temp files redirect",  ".*/temp/([^/]*)$",     LDFL_OP_MAP,      "/tmp/$1",            LDFL_PATH_ABS,  NULL                   },
    { "inc redirect",         "(.*)/inc/(.*)",        LDFL_OP_MAP,      "$1/lib/$2",          LDFL_PATH_ABS,  NULL                   },
    { "executable redirect",  ".*/.bin/\\([^/]*\\)$", LDFL_OP_EXEC_MAP, "/opt/ldfl/bin/\\1", LDFL_PATH_ABS,  NULL                   },
    { "memory open",          ".*/file[0-9].txt",     LDFL_OP_MEM_OPEN, NULL,                 LDFL_PATH_ABS,  NULL                   },
    { "static file",          ".*/static.bin",        LDFL_OP_STATIC,   ldf_default_blob,     LDFL_PATH_ABS,  NULL                   },
    { "change data perm",     ".*/data/.*",           LDFL_OP_PERM,     NULL,                 LDFL_PATH_ABS,  "kakwa:kakwa|0700|0600"},
    { "allow /dev",           "^/dev/.*",             LDFL_OP_NOOP,     NULL,                 LDFL_PATH_ABS,  NULL                   },
    { "allow /proc",          "^/proc/.*",            LDFL_OP_NOOP,     NULL,                 LDFL_PATH_ABS,  NULL                   },
    { "allow /sys",           "^/sys/.*",             LDFL_OP_NOOP,     NULL,                 LDFL_PATH_ABS,  NULL                   },
    { "default & deny",       ".*",                   LDFL_OP_DENY,     NULL,                 LDFL_PATH_ABS,  NULL                   },
    { NULL,                   NULL,                   LDFL_OP_END,      NULL,                 LDFL_PATH_ABS,  NULL                   }  // keep this last value
};


ldfl_setting_t ldfl_setting = {
    .log_mask    = LDFL_LOG_MAPPING_RULE_FOUND | LDFL_LOG_FN_CALL | LDFL_LOG_INIT | LDFL_LOG_MAPPING_RULE_APPLY | LDFL_LOG_FN_CALL_ERR,
    .log_level   = LOG_DEBUG,
    .logger      = ldfl_syslog_logger,
};
