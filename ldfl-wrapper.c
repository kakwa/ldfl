#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <argp.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#include <fcntl.h>
#include <io.h>
#define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384

#ifndef DEFAULT_LIB_PATH
#define DEFAULT_LIB_PATH "libldfl.so"
#endif

const char *argp_program_version = BFD_VERSION;

const char *argp_program_bug_address = "https://github.com/kakwa/ldfl/issues";

static char doc[] = "\nLDFL - libldfl.so LD_PRELOAD wrapper for path remapping";

static struct argp_option options[] = {
    {"config", 'c', "CONFIG_FILE", 0, "Configuration file for path remapping"},
    {"library", 'l', "LIBRARY_PATH", 0, "Path to the ldfl library (default: " DEFAULT_LIB_PATH ")"},
    {"debug", 'd', NULL, 0, "Debug Output"},
    {0}};

/* A description of the arguments we accept. */
static char args_doc[] = "-c CONFIG_FILE -- COMMAND [ARGS...]";

struct arguments {
    char  *config_file;
    char  *library_path;
    bool   debug;
    char  *command;
    char **command_args;
    int    command_argc;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'c':
        arguments->config_file = arg;
        break;
    case 'l':
        arguments->library_path = arg;
        break;
    case 'd':
        arguments->debug = true;
        break;
    case ARGP_KEY_ARGS:
        arguments->command_argc = state->argc - state->next;
        arguments->command_args = calloc(arguments->command_argc + 1, sizeof(char *));
        if (!arguments->command_args) {
            argp_failure(state, 1, ENOMEM, "Memory allocation failed");
        }
        for (int i = 0; i < arguments->command_argc; i++) {
            arguments->command_args[i] = state->argv[state->next + i];
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

// Function to validate arguments
int validate_arguments(struct arguments *args) {
    if (!args->config_file) {
        fprintf(stderr, "Error: Configuration file is required (-c)\n");
        return 1;
    }

    if (!args->command_args || args->command_argc < 1) {
        fprintf(stderr, "Error: Command is required after --\n");
        return 1;
    }

    return 0;
}

// Function to setup environment variables
int setup_environment(struct arguments *args, char **abs_config_path, char **abs_library_path) {
    // Get absolute path for config file
    *abs_config_path = realpath(args->config_file, NULL);
    if (!*abs_config_path) {
        fprintf(stderr, "Error: Cannot resolve config file path '%s': %s\n", args->config_file, strerror(errno));
        return 1;
    }

    if (args->debug) {
        fprintf(stderr, "Debug: Config file absolute path: %s\n", *abs_config_path);
    }

    // Check if library exists in current directory
    if (args->library_path == NULL) {
        if (access("./libldfl.so", F_OK) == 0) {
            args->library_path = "./libldfl.so";
            if (args->debug) {
                fprintf(stderr, "Debug: Found LDFL library in current directory: %s, using it\n", args->library_path);
            }
        } else {
            args->library_path = DEFAULT_LIB_PATH;
            if (args->debug) {
                fprintf(stderr, "Debug: Using default LDFL library path '%s'\n", args->library_path);
            }
        }
    }

    // Get absolute path for library
    *abs_library_path = realpath(args->library_path, NULL);
    if (!*abs_library_path) {
        fprintf(stderr, "Error: Cannot resolve library path '%s': %s\n", args->library_path, strerror(errno));
        free(*abs_config_path);
        return 1;
    }

    if (args->debug) {
        fprintf(stderr, "Debug: Library absolute path: %s\n", *abs_library_path);
    }

    // Set LDFL_CONFIG
    if (setenv("LDFL_CONFIG", *abs_config_path, 1) != 0) {
        fprintf(stderr, "Error setting LDFL_CONFIG: %s\n", strerror(errno));
        free(*abs_config_path);
        free(*abs_library_path);
        return 1;
    }

    if (args->debug) {
        fprintf(stderr, "Debug: Set LDFL_CONFIG=%s\n", *abs_config_path);
    }

    // Set LD_PRELOAD to point to our library
    if (setenv("LD_PRELOAD", *abs_library_path, 1) != 0) {
        fprintf(stderr, "Error setting LD_PRELOAD: %s\n", strerror(errno));
        free(*abs_config_path);
        free(*abs_library_path);
        return 1;
    }

    if (args->debug) {
        fprintf(stderr, "Debug: Set LD_PRELOAD=%s\n", *abs_library_path);
        fprintf(stderr, "Debug: Executing command: ");
        for (int i = 0; i < args->command_argc; i++) {
            fprintf(stderr, "%s ", args->command_args[i]);
        }
        fprintf(stderr, "\n");
    }

    return 0;
}

#ifndef LDLF_TESTING
int main(int argc, char **argv) {
    struct arguments args             = {0};
    char            *abs_config_path  = NULL;
    char            *abs_library_path = NULL;

    // Set default library path
    args.library_path = NULL;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (args.debug) {
        fprintf(stderr, "Debug: Starting ldfl-wrapper\n");
        fprintf(stderr, "Debug: Config file: %s\n", args.config_file);
    }

    // Validate arguments
    if (validate_arguments(&args) != 0) {
        return 1;
    }

    // Setup environment
    if (setup_environment(&args, &abs_config_path, &abs_library_path) != 0) {
        return 1;
    }

    // Free allocated memory
    free(abs_config_path);
    free(abs_library_path);

    // Execute the command
    execvp(args.command_args[0], args.command_args);

    // If we get here, exec failed
    fprintf(stderr, "Error executing command: %s\n", strerror(errno));
    return 1;
}
#endif
