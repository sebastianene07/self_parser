#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define NUM_CMD_ACTIONS         (4)

#define MAX_NUM_CMD_ARGS        (10)
#define MAX_CMD_ARG_SIZE        (32)

#define ELF_SIGNATURE   {0x7F, 0x45, 0x4C, 0x46}

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

static volatile int g_run_forever = 1;

typedef int (* cb_action)(int argc, char **argv);

typedef struct cmd_action_s
{
    cb_action action;       /* The action to execute */
    const char *cmd_name;   /* The command name */
    const char *cmd_help;   /* The help printed on command failure */
} cmd_action_t;

typedef union
{
    Elf64_Ehdr elf64_hdr;
    Elf32_Ehdr elf32_hdr;
} elf_hdr_t;

typedef union
{
    Elf32_Phdr elf32_phdr;
    Elf64_Phdr elf64_phdr;    
} elf_phdr_t;

typedef struct sinject_ctxt_s
{
    int target_fd;
    void *target_elf_ptr;
    size_t target_size;
    int payload_fd;
    void *payload_ptr;
    size_t payload_size;
    void *target_text_segment; /* program hdr of the RE segment for the memory mapped target ELF */
    size_t max_payload_size; /* max payload size to the next segment boundry */
} sinject_ctxt_t;

static int cb_action_help(int argc, char **argv);
static int cb_action_quit(int argc, char **argv);
static int cb_action_select_target_elf(int argc, char **argv);
static int cb_action_select_payload(int argc, char **argv);
static int cb_action_method_fini_append(int argc, char **argv);
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
        .action     = cb_action_select_payload,
        .cmd_name   = "select_payload",
        .cmd_help   = "Select the payload that you want to inject <payload_path>",
    },
    {
        .action     = cb_action_method_fini_append,
        .cmd_name   = "inject_fini",
        .cmd_help   = "Append the payload after .fini section if there is space\n"
                      "\t\t\tand update the entry point to run the payload first and\n"
                      "\t\t\tthen redirect execution to the old entry point. \n"
                      "\t\t\tNOTE: the payload that we want to load has to return !\n"
    },
    {
        .action     = cb_action_write_patch_target,
        .cmd_name   = "update_target",
        .cmd_help   = "Write the patched target to a new file <elf_path> "
                      "and close the selected target"
    },
};

const unsigned char elf_signature[] = ELF_SIGNATURE;

static void do_print_welcome(void)
{
    printf("Press CTRL-C or q to stop, for help press ? or type help\n");
}

static void do_context_destroy(void)
{
    if (g_sinject_context.target_elf_ptr) {
        munmap(g_sinject_context.target_elf_ptr, g_sinject_context.target_size);
    }

    if (g_sinject_context.payload_ptr) {
        munmap(g_sinject_context.payload_ptr, g_sinject_context.payload_size);
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

static int open_and_map_file(const char *file_name, int *fd, size_t *file_size,
                             void **mapped_mem)
{
    struct stat sb;

    *fd = open(file_name, O_RDWR, 0);
    if (*fd < 0) {
        printf("error open %s\n", file_name);
        return -1;
    }

    /* Get the file size and map the entire file in memory*/

    fstat(*fd, &sb);
    *file_size = sb.st_size;
    *mapped_mem = mmap(NULL, *file_size,
                       PROT_READ | PROT_WRITE,
                       MAP_FILE | MAP_SHARED,
                       *fd, 0);
    if (g_sinject_context.target_elf_ptr == MAP_FAILED) {
        printf("map error fd %d size %lu\n", g_sinject_context.target_fd,
               g_sinject_context.target_size);
        g_sinject_context.target_elf_ptr = NULL;
        return -1;
    }

    return 0;
}

static int find_re_segment(elf_hdr_t *hdr, void **out)
{
    if (hdr->elf64_hdr.e_machine == EM_386) {
        Elf32_Phdr *iter_phdr;
        Elf32_Phdr *base = (void *)hdr + hdr->elf32_hdr.e_phoff;
        for (iter_phdr = base; iter_phdr < base + hdr->elf32_hdr.e_phnum; iter_phdr++) {
            if (iter_phdr->p_type == PT_LOAD && iter_phdr->p_flags & PF_X && iter_phdr->p_flags & PF_R) {
                *out = (void *)iter_phdr;
                return 0;
            }    
        }
    } else if (hdr->elf64_hdr.e_machine == EM_X86_64) {
        Elf64_Phdr *iter_phdr;
        Elf64_Phdr *base = (void *)hdr + hdr->elf64_hdr.e_phoff;
        for (iter_phdr = base; iter_phdr < base + hdr->elf64_hdr.e_phnum; iter_phdr++) {
            if (iter_phdr->p_type == PT_LOAD && iter_phdr->p_flags & PF_X && iter_phdr->p_flags & PF_R) {
                *out = (void *)iter_phdr;
                return 0;
            }    
        }
    }

    return -1;
}

static int cb_action_select_target_elf(int argc, char **argv)
{
    int ret;
    elf_hdr_t *target_elf_hdr;
    off_t payload_start_offset;

    ret = open_and_map_file(argv[1], &g_sinject_context.target_fd,
                            &g_sinject_context.target_size,
                            &g_sinject_context.target_elf_ptr);
    if (ret < 0) {
        printf("ERROR %d something went wrong open_target\n", ret);
        return ret;
    }

    target_elf_hdr = g_sinject_context.target_elf_ptr;
    if (memcmp(target_elf_hdr->elf64_hdr.e_ident, elf_signature,
        sizeof(elf_signature)) != 0) {
        printf("ERROR target not an ELF file\n");
        return -1;
    }

    ret = find_re_segment(target_elf_hdr, &g_sinject_context.target_text_segment);
    if (ret) {
        printf("ERROR segment RE not found\n");
        return -1;
    }

    if (target_elf_hdr->elf64_hdr.e_machine == EM_386) {
        printf("[*] Found 32-bit target ELF\n");
        Elf32_Phdr *iter_phdr = g_sinject_context.target_text_segment;
        payload_start_offset = iter_phdr->p_offset + iter_phdr->p_memsz;
        g_sinject_context.max_payload_size = (iter_phdr + 1)->p_offset -
            payload_start_offset;
    } else if (target_elf_hdr->elf64_hdr.e_machine == EM_X86_64) {
        printf("[*] Found 64-bit target ELF\n");
        Elf64_Phdr *iter_phdr = g_sinject_context.target_text_segment;
        payload_start_offset = iter_phdr->p_offset + iter_phdr->p_memsz;
        g_sinject_context.max_payload_size = (iter_phdr + 1)->p_offset -
            payload_start_offset;
    }

    printf("[*] Found max payload size: %lu\n", g_sinject_context.max_payload_size);

    return 0;    
}

static int cb_action_select_payload(int argc, char **argv)
{
    return open_and_map_file(argv[1], &g_sinject_context.payload_fd,
                             &g_sinject_context.payload_size,
                             &g_sinject_context.payload_ptr);
}

/*
 * Find the RE segment in the payload and copy it to the end of .fini from the
 * target ELF. Update entry point to point to the newly inserted
 * 'payload entrypoint' end then append a call instruction to redirect execution to
 * the old entrypoint from the target payload.
 */
static int cb_action_method_fini_append(int argc, char **argv)
{
    elf_hdr_t *target_elf_hdr, *payload_elf_hdr;
    void *payload_text_segment, **old_entrypoint, *copy_dest, *payload_entrypoint;
    void *target_fini_end = NULL, *old_target_entrypoint, *payload_text_offset;
    unsigned char *instr_patch_abs;
    int ret;
    size_t payload_size = 0;

    if (!g_sinject_context.target_elf_ptr) {
        printf("ERROR Missing target - Use 'select_target' <elf_target_path>\n");
        return -1;
    }

    if (!g_sinject_context.payload_ptr) {
        printf("ERROR Missing payload - Use 'select_payload' <elf_target_path>\n");
        return -1;
    }

    payload_elf_hdr = g_sinject_context.payload_ptr;
    target_elf_hdr = g_sinject_context.target_elf_ptr;

    ret = find_re_segment(payload_elf_hdr, &payload_text_segment);
    if (ret) {
        printf("ERROR segment RE not found in payload\n");
        return -1;
    }

    /* Figure out the size of the text payload */
    if (payload_elf_hdr->elf64_hdr.e_machine == EM_386) {
        payload_size = ((Elf32_Phdr *)payload_text_segment)->p_memsz;
        payload_entrypoint = (void *)(intptr_t)payload_elf_hdr->elf32_hdr.e_entry;
        payload_text_offset = ((Elf32_Phdr *)payload_text_segment)->p_offset + g_sinject_context.payload_ptr;
    } else if (payload_elf_hdr->elf64_hdr.e_machine == EM_X86_64) {
        payload_size = ((Elf64_Phdr *)payload_text_segment)->p_memsz;
        payload_entrypoint = (void *)payload_elf_hdr->elf64_hdr.e_entry;
        payload_text_offset = ((Elf64_Phdr *)payload_text_segment)->p_offset + g_sinject_context.payload_ptr;
    }

    printf("[*] Payload .text size %lu\n", payload_size);
    printf("[*] Payload entrypoint %p\n", payload_entrypoint);

    /* Save the old entrypoint and figure out .fini end position */
    if (target_elf_hdr->elf64_hdr.e_machine == EM_386) {
        Elf32_Phdr *phdr = g_sinject_context.target_text_segment;
        old_entrypoint = (void **)&target_elf_hdr->elf32_hdr.e_entry;
        target_fini_end = (void *)(intptr_t)(phdr->p_offset + phdr->p_memsz);
    } else if (target_elf_hdr->elf64_hdr.e_machine == EM_X86_64) {
        Elf64_Phdr *phdr = g_sinject_context.target_text_segment;
        old_entrypoint = (void **)&target_elf_hdr->elf64_hdr.e_entry;
        target_fini_end = (void *)(phdr->p_offset + phdr->p_memsz);
    }

    printf("[*] Append at %p\n", target_fini_end);
    copy_dest = target_fini_end + (unsigned long)g_sinject_context.target_elf_ptr;
    printf("[*] Old target entrypoint at %p\n", *old_entrypoint);
    old_target_entrypoint = *old_entrypoint;
    *old_entrypoint = (payload_entrypoint - (payload_text_offset - (unsigned long)g_sinject_context.payload_ptr)) + target_fini_end;
    printf("[*] New entrypoint at %p\n", *old_entrypoint);
    
    memcpy(copy_dest, payload_text_offset, payload_size);

    /*
     * Find the nop chain in the payload and patch a call instruction to the original
     * entry point from the target ELF. We start searching the nop chain from the new
     * entry point.
     * */
    void *entry_point_abs = *old_entrypoint + (unsigned long)g_sinject_context.target_elf_ptr;
    size_t search_sz = payload_size - (payload_entrypoint - (payload_text_offset - (unsigned long)g_sinject_context.payload_ptr));
    unsigned char nop_chain[4] = {0x90, 0x90, 0x90, 0x90};
    instr_patch_abs = memmem(entry_point_abs, search_sz, nop_chain, sizeof(nop_chain));
    if (!instr_patch_abs) {
        printf("ERROR: nop-chain not found in payload\n");
        return -1;
    }

    size_t instr_patch_rel = (unsigned long)instr_patch_abs - (unsigned long)g_sinject_context.target_elf_ptr;
    printf("[*] Patch nop-chain with call at %lx", instr_patch_rel);
    unsigned int addend = (unsigned int)(intptr_t)old_target_entrypoint - instr_patch_rel - 11;
    *instr_patch_abs++ = 0x5a;  // pop %rdx
    *instr_patch_abs++ = 0x58;  // pop %rax

    *instr_patch_abs++ = 0x48;  // mov    %rbp,%rsp
    *instr_patch_abs++ = 0x89;
    *instr_patch_abs++ = 0xec;

    *instr_patch_abs++ = 0x5d;  // pop %rbp

    *instr_patch_abs++ = 0xe9;  // jmp to original entry point
    memcpy(instr_patch_abs, &addend, sizeof(addend));

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
