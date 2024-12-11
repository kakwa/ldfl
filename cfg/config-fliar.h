static const mapping_t mappings[] = {
    /* name                  search_pattern               type                   replace_pattern   target         */
    {"temporary redirect", ".*/temporary/\\([^/]*\\)$", MAPPING_TYPE_REGEX, "/tmp/\\1", NULL},
    {"memory open", ".*/file[0-9].txt", MAPPING_TYPE_MEM_OPEN, NULL, NULL},
    {"static file", ".*/static.bin", MAPPING_TYPE_STATIC, NULL, default_blob},
    {"default deny", ".*", MAPPING_TYPE_DENY, NULL, NULL}};

static const settings_t settings = {.log_level = "debug", .cache_first = true};

static const configuration_t config = {
    .settings = settings, .mappings = mappings, .mappings_count = sizeof(mappings) / sizeof(mappings[0])};

/* ADDITIONAL BLOBS */
