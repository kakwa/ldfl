static const unsigned char ldf_default_blob[] = "hello from ldfl";

ldfl_mapping_t ldfl_mapping[] = {
    /* name                     search pattern           operation            target                input path mode  final rule  extra options           */
    {  "files redirect",        ".*/temp/([^/]*)$",      LDFL_OP_PATH_REDIR,  "/tmp/$1",            LDFL_PATH_ABS,   true,       NULL                     },
    {  "executable redirect",   ".*/.bin/\\([^/]*\\)$",  LDFL_OP_EXEC_REDIR,  "/opt/ldfl/bin/\\1",  LDFL_PATH_ABS,   true,       NULL                     },
    {  "memory open (no abs)",  "file[0-9].txt",         LDFL_OP_MEM_OPEN,    NULL,                 LDFL_PATH_ORIG,  true,       NULL                     },
    {  "memory, set data",      ".*/static.bin",         LDFL_OP_MEM_DATA,    ldf_default_blob,     LDFL_PATH_ABS,   true,       NULL                     },
    {  "change data perm",      ".*/data/.*",            LDFL_OP_PERM,        NULL,                 LDFL_PATH_ABS,   true,       "kakwa:kakwa|0700|0600"  },
    {  "redir to fake /dev",    "^/dev/.*",              LDFL_OP_PATH_REDIR,  "/home/fakedev/$1",   LDFL_PATH_ABS,   false,      NULL                     },
    {  "force /dev read only",  "^/dev/.*",              LDFL_OP_RO,          NULL,                 LDFL_PATH_ABS,   true,       NULL                     },
    {  "no op on /sys" ,        "^/sys/.*",              LDFL_OP_NOOP,        NULL,                 LDFL_PATH_ABS,   true,       NULL                     },
    {  "default & deny",        ".*",                    LDFL_OP_DENY,        NULL,                 LDFL_PATH_ABS,   true,       NULL                     },
    {  NULL,                    NULL,                    LDFL_OP_END,         NULL,                 LDFL_PATH_ABS,   true,       NULL                     } // keep this last value
};

ldfl_setting_t ldfl_setting = {
    .log_mask  = LDFL_LOG_RULE_FOUND | LDFL_LOG_FN_CALL | LDFL_LOG_INIT | LDFL_LOG_RULE_APPLY | LDFL_LOG_FN_CALL_ERR,
    .log_level = LOG_DEBUG,
    .logger    = ldfl_syslog_logger,
};
