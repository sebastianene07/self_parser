#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define NUM_CMD_ACTIONS         (4)

#define MAX_NUM_CMD_ARGS        (10)
#define MAX_CMD_ARG_SIZE        (32)

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

static volatile int g_run_forever = 1;

typedef int (* cb_action)(int argc, char **argv);

typedef struct cmd_action_s
{
    cb_action action;       /* The action to execute */
    const char *cmd_name;   /* The command name */
    const char *cmd_help;   /* The help printed on command failure */
} cmd_action_t;

typedef struct sinject_ctxt_s
{
    int target_fd;
    void *target_mem;
    size_t target_size;
    int payload_fd;
    void *payload_mem;
    size_t payload_size;
} sinject_ctxt_t;

static int cb_action_help(int argc, char **argv);
static int cb_action_quit(int argc, char **argv);
static int cb_action_select_target_elf(int argc, char **argv);
static int cb_action_select_inject_payload(int argc, char **argv);
static int cb_action_patch_target(int argc, char **argv);
static int cb_action_write_patch_target(int argc, char **argv);

static sinject_ctxt_t g_sinject_context;

static cmd_action_t g_cmd_actions[] =
{
    {
        .action     = cb_action_help,
        .cmd_name   = "help",
        .cmd_help   = "Prints the help menu",
    },
    {
        .action     = cb_action_help,
        .cmd_name   = "?",
        .cmd_help   = "Prints the help menu",
    },
    {
        .action     = cb_action_quit,
        .cmd_name   = "q",
        .cmd_help   = "Quit",
    },
    {
        .action     = cb_action_select_target_elf,
        .cmd_name   = "select_target",
        .cmd_help   = "Select the ELF target that you want to modify <elf_path>",
    },
    {
        .action     = cb_action_select_inject_payload,
        .cmd_name   = "select_payload",
        .cmd_help   = "Select the payload that you want to inject <payload_path>",
    },
    {
        .action     = cb_action_patch_target,
        .cmd_name   = "patch_target",
        .cmd_help   = "Patch the target by adding a new section at the end "
                      "of the elf, and modify the NOTE segement to be LOAD "
                      "with XRW permissions"
    },
    {
        .action     = cb_action_write_patch_target,
        .cmd_name   = "update_target",
        .cmd_help   = "Write the patched target to a new file <elf_path> "
                      "and close the selected target"
    },
};

static void do_print_welcome(void)
{
    printf("Press CTRL-C or q to stop, for help press ? or type help\n");
}

static void do_context_destroy(void)
{
    if (g_sinject_context.target_mem) {
        munmap(g_sinject_context.target_mem, g_sinject_context.target_size);
    }

    if (g_sinject_context.payload_mem) {
        munmap(g_sinject_context.payload_mem, g_sinject_context.payload_size);
    }

    if (g_sinject_context.target_fd) {
        close(g_sinject_context.target_fd);
    }

    if (g_sinject_context.payload_fd) {
        close(g_sinject_context.payload_fd);
    }
}

static void do_terminate_handler(int not_used)
{
    (void)(not_used);
    g_run_forever = 0;
}

static int cb_action_help(int argc, char **argv)
{
    int i;

    printf("help menu:\n");
    for (i = 0; i < ARRAY_LEN(g_cmd_actions); i++) {
        printf("\t%s : %s\n", g_cmd_actions[i].cmd_name,
               g_cmd_actions[i].cmd_help);
    }

    return 0;
}

static int cb_action_quit(int argc, char **argv)
{
    g_run_forever = 0;
    return 0;
}

static int cb_action_select_target_elf(int argc, char **argv)
{
    struct stat sb;

    g_sinject_context.target_fd = open(argv[1], O_RDWR, 0);
    if (g_sinject_context.target_fd < 0) {
        printf("error open %s\n", argv[1]);
        return -1;
    }

    /* Get the file size and map the entire file in memory*/

    fstat(g_sinject_context.target_fd, &sb);
    g_sinject_context.target_size = sb.st_size;
    g_sinject_context.target_mem = mmap(NULL, g_sinject_context.target_size,
                                        PROT_READ | PROT_WRITE,
                                        MAP_FILE | MAP_SHARED,
                                        g_sinject_context.target_fd, 0);
    if (g_sinject_context.target_mem == MAP_FAILED) {
        printf("map error fd %d size %lu\n", g_sinject_context.target_fd,
               g_sinject_context.target_size);
        g_sinject_context.target_mem = NULL;
        return -1;
    }

    return 0;
}

static int cb_action_select_inject_payload(int argc, char **argv)
{
    struct stat sb;

    g_sinject_context.payload_fd = open(argv[1], O_RDWR, 0);
    if (g_sinject_context.payload_fd < 0) {
        printf("error open %s\n", argv[1]);
        return -1;
    }

    /* Get the file size and map the entire file in memory*/

    fstat(g_sinject_context.payload_fd, &sb);
    g_sinject_context.payload_size = sb.st_size;
    g_sinject_context.payload_mem = mmap(NULL, g_sinject_context.payload_size,
                                        PROT_READ | PROT_WRITE,
                                        MAP_FILE | MAP_SHARED,
                                        g_sinject_context.payload_fd, 0);
    if (g_sinject_context.payload_mem == MAP_FAILED) {
        printf("map error fd %d size %lu\n", g_sinject_context.payload_fd,
               g_sinject_context.payload_size);
        g_sinject_context.payload_mem = NULL;
        return -1;
    }

    return 0;
}

static int cb_action_patch_target(int argc, char **argv)
{
    /* Check if we have a target and a payload opened */

    if (!g_sinject_context.payload_mem) {
        printf("Missing payload - Use 'select_payload' <elf_payload_path>\n");
        return -1;
    }

    if (!g_sinject_context.target_mem) {
        printf("Missing target - Use 'select_target' <elf_target_path>\n");
        return -1;
    }

    
    return 0;
}

static int cb_action_write_patch_target(int argc, char **argv)
{
    return 0;
}

static void parse_cmd_buffer(char *cmd_arg_buffer, int num_cmd_args)
{
    int i, j;
    bool is_cmd_found = false;
    char *argv[MAX_NUM_CMD_ARGS];

    memset(argv, 0, sizeof(char *) * MAX_NUM_CMD_ARGS);

    for (i = 0; i < ARRAY_LEN(g_cmd_actions); i++) {
        if (strcmp(cmd_arg_buffer, g_cmd_actions[i].cmd_name) == 0) {

            /* Copy the pointer to the args in the argv buffer */

            for (j = 0; j < num_cmd_args; j++) {
                argv[j] = &cmd_arg_buffer[j * MAX_CMD_ARG_SIZE];
            }

            is_cmd_found = true;
            g_cmd_actions[i].action(num_cmd_args, (char **)&argv);
            break;
        }
    }

    if (is_cmd_found == false) {
        printf("Unknown command: %s\n", cmd_arg_buffer);
    }
}

int main(int argc, char **argv)
{
    int ch;
    int num_cmd_args;
    int byte_arg_indx;
    char cmd_arg_buffer[MAX_NUM_CMD_ARGS][MAX_CMD_ARG_SIZE];

    /* Register a signal handler to catch CTRL-C */

    signal(SIGINT, do_terminate_handler);

    do_print_welcome();

    while (g_run_forever) {
        printf("\n>> ");

        num_cmd_args  = 0;
        byte_arg_indx = 0;

        /* Get a line in the input buffer */

        do {
            ch = getchar();

            if (ch == ' ') {
                cmd_arg_buffer[num_cmd_args][byte_arg_indx++] = '\0';
                num_cmd_args  = (num_cmd_args + 1) % MAX_NUM_CMD_ARGS;
                byte_arg_indx = 0;
            } else {
                cmd_arg_buffer[num_cmd_args][byte_arg_indx++] = (char)ch;
                byte_arg_indx = byte_arg_indx % MAX_CMD_ARG_SIZE;
            }
        } while (ch != '\n' && g_run_forever);

        /* If there are no supplied arguments just continue executing */

        if (num_cmd_args == 0 && byte_arg_indx <= 1)
            continue;

        cmd_arg_buffer[num_cmd_args][byte_arg_indx - 1] = '\0';
        num_cmd_args  = (num_cmd_args + 1) % MAX_NUM_CMD_ARGS;

        /* Parse the command arg buffer */

        parse_cmd_buffer((char *)&cmd_arg_buffer, num_cmd_args);
    }

    do_context_destroy();
    return 0;
}
