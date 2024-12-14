const ldfl_mapping_t ldfl_mapping[] = {
    /* name                  search_pattern          operation         target                extra_options         */
    { "temporary redirect",  ".*/temp/\\([^/]*\\)$", LDFL_OP_MAP,      "/tmp/\\1",           NULL},
    { "executable redirect", ".*/.bin/\\([^/]*\\)$", LDFL_OP_EXEC_MAP, "/opt/fliar/bin/\\1", NULL},
    { "memory open",         ".*/file[0-9].txt",     LDFL_OP_MEM_OPEN, NULL,                 NULL},
    { "static file",         ".*/static.bin",        LDFL_OP_STATIC,   ldf_default_blob,     NULL},
    { "change perm/owner",   ".*/data/.*",           LDFL_OP_PERM,     NULL,                 "kakwa:kakwa|0700|0600"},
    { "default deny",        ".*",                   LDFL_OP_DENY,     NULL,                 NULL},
    { NULL,                  NULL,                   LDFL_OP_END,      NULL,                 NULL} // keep this last value
};

const ldfl_setting_t ldfl_setting = {
    .log_level   = LOG_DEBUG,
    .logger      = ldfl_stderr_logger,
};

/* ADDITIONAL BLOBS */
