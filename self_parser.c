#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ELF_SIGNATURE   {0x7F, 0x45, 0x4C, 0x46}
#define ELF_HEADER_NUM  (1)

#define ELF_SYMTAB_NAME ".strtab"

static const char g_sh_type_names[SHT_NUM][13] = {
    "SHT_NULL",
    "SHT_PROGBITS",
    "SHT_SYMTAB",   /* This section holds a symbol table */
    "SHT_STRTAB",   /* This section holds a string table */
    "SHT_RELA",
    "SHT_HASH",
    "SHT_DYNAMIC",
    "SHT_NOTE",
    "SHT_NOBITS",
    "SHT_REL",
    "SHT_SHLIB",
    "SHT_DYNSIM",
};

static void print_help(void)
{
    printf("self_parser - A simple ELF parser\n"
           "Expected input: <path_to_elf>\n");
    exit(1);
}

static const char *get_section_name_from_type(int sh_type)
{
    if (sh_type < SHT_NUM)
        return g_sh_type_names[sh_type];
    else if (sh_type == SHT_LOPROC)
        return "SHT_LOPROC";
    else if (sh_type == SHT_HIPROC)
        return "SHT_HIPROC";
    else if (sh_type == SHT_LOUSER)
        return "SHT_LOUSER";
    else if (sh_type == SHT_HIUSER)
        return "SHT_HIUSER";
    else
        return "SHT_UNKNOWN";
}

static unsigned char *get_section_data(Elf32_Shdr *sh, FILE *f_elf)
{
    int ret;
    size_t nread;
    unsigned char *section_data = calloc(1, sh->sh_size);
    if (section_data == NULL) {
        return NULL;
    }

    ret = fseek(f_elf, (long int)sh->sh_offset, SEEK_SET);
    if (ret != 0) {
        printf("Cannot seek to symbol string table\n");
        free(section_data);
        return NULL;
    }

    nread = fread(section_data, 1, sh->sh_size, f_elf);
    if (nread != sh->sh_size) {
        printf("Error reading section %d\n", sh->sh_name);
        free(section_data);
        return NULL;
    }

    return section_data;
}

static int parse_elf(char *elf_path)
{
    int ret = 0, str_symtab_index = -1, symtab_index = -1;
    FILE *f_elf;
    size_t nread, section_headers_len, symbol_num;
    Elf32_Ehdr elf_header;
    Elf32_Shdr *section_header;
    Elf32_Shdr *sh_strtab, *sh_strsymtab, *sh_symtab;

    f_elf = fopen(elf_path, "r");
    if (f_elf == NULL) {
        printf("Invalid file: %s\n", elf_path);
        return -EINVAL;
    }

    /* Read the ELF header */

    nread = fread(&elf_header, sizeof(Elf32_Ehdr), ELF_HEADER_NUM, f_elf);
    if (nread != ELF_HEADER_NUM) {
        printf("Read header error from file: %s\n", elf_path);
        ret = -EINVAL;
        goto errout_with_file;
    }

    /* Check the ELF signature */

    unsigned char elf_signature[] = ELF_SIGNATURE;
    if (memcmp(&elf_header.e_ident[EI_MAG0],
               elf_signature,
               sizeof(elf_signature))) {
        printf("File %s not an ELF executable\n", elf_path);
        ret = -EINVAL;
        goto errout_with_file;
    }

    if (elf_header.e_type != ET_EXEC) {
        printf("File %s not an executable ELF, e_type=%d\n", elf_path,
                elf_header.e_type);
        ret = -EINVAL;
        goto errout_with_file;
    }

    /* Look for the section headers */

    if (elf_header.e_shoff == 0 ||
        elf_header.e_shnum == 0) {
        printf("File %s has no section headers\n", elf_path);
        ret = -EINVAL;
        goto errout_with_file;
    }

    /* Check support ELF 32 bit sections */

    if (elf_header.e_shentsize != sizeof(Elf32_Shdr))
    {
        printf("Section size %d not supported\n", elf_header.e_shentsize);
        ret = -EINVAL;
        goto errout_with_file;
    }

    /* Allocate space for the section header table and read it */

    section_header = calloc(sizeof(Elf32_Shdr), elf_header.e_shnum);
    if (section_header == NULL) {
        ret = -ENOMEM;
        goto errout_with_file;
    }

    section_headers_len = elf_header.e_shentsize * elf_header.e_shnum;
    printf("Found %d section headers at offset 0x%x total size (bytes):%ld\n\n",
           elf_header.e_shnum,
           elf_header.e_shoff,
           section_headers_len);

    ret = fseek(f_elf, (long int)elf_header.e_shoff, SEEK_SET);
    if (ret != 0) {
        printf("Cannot seek to section header table\n");
        goto errout_with_shdr;
    }

    nread = fread(section_header,
                  elf_header.e_shentsize,
                  elf_header.e_shnum,
                  f_elf);
    if (nread != elf_header.e_shnum) {
        printf("Read section header error from file: %s\n", elf_path);
        ret = -EINVAL;
        goto errout_with_shdr;
    }

    /* Get the section string table: .shtrtab */

    sh_strtab = &section_header[elf_header.e_shstrndx];
    unsigned char *sh_strtab_data = get_section_data(sh_strtab, f_elf);
    if (sh_strtab_data == NULL) {
        ret = -ENOMEM;
        goto errout_with_shdr;
    }

    /* Parse section headers */

    for (int i = 0; i < elf_header.e_shnum; i++) {
        int sh_type = section_header[i].sh_type;
        int sh_name_index = section_header[i].sh_name;
        char *sh_name = (char *)sh_strtab_data + sh_name_index;

        printf("Section [%d] name: %s type :%s\n", i,
               *sh_name == '\0' ? "NO_NAME" : sh_name,
               get_section_name_from_type(sh_type));

        /* Save the index of the string symbol table */

        if (sh_type == SHT_STRTAB &&
            !strcmp(sh_name, ELF_SYMTAB_NAME)) {
            str_symtab_index = i;
        }

        /* Save the index of the symbol table */

        if (sh_type == SHT_SYMTAB) {
            symtab_index = i;
        }
    }

    if (symtab_index < 0) {
        printf("No symbol table found!\n");
        ret = -EINVAL;
        goto errout_with_strtab;
    }

    if (str_symtab_index < 0) {
        printf("No string symbol table found .strtab missing!\n");
        ret = -EINVAL;
        goto errout_with_strtab;
    }

    /* Get the section that holds the symbol names: .strtab */

    sh_strsymtab = &section_header[str_symtab_index];
    unsigned char *sh_strsymtab_data = get_section_data(sh_strsymtab, f_elf);
    if (sh_strsymtab_data == NULL) {
        ret = -EINVAL;
        goto errout_with_strtab;
    }

    /* Get the section that holds symbols information: .symtab */

    sh_symtab = &section_header[symtab_index];
    unsigned char *sh_symtab_data = get_section_data(sh_symtab, f_elf);
    if (sh_symtab_data == NULL) {
        ret = -EINVAL;
        goto errout_with_strsymtab;
    }

    /* Iterate over the symbol table elements */

    symbol_num = sh_symtab->sh_size / sh_symtab->sh_entsize;
    printf("\nFound: %ld symbols in .symtab\n", symbol_num);

    for (int i = 0; i < symbol_num; i++) {
        Elf32_Sym *sym_entry = (Elf32_Sym *)sh_symtab_data + i;

        char *sym_name = (char *)sh_strsymtab_data + sym_entry->st_name;
        int sym_type = ELF32_ST_TYPE(sym_entry->st_info);

        if (sym_entry->st_size > 0) {
            printf("%64s | start:%8x | length:%8u bytes ",
                   sym_name,
                   sym_entry->st_value,
                   sym_entry->st_size);

            if (sym_type == STT_OBJECT)
                printf("type: STT_OBJECT\n");
            else if (sym_type == STT_FUNC)
                printf("type: STT_FUNC\n");
            else
                printf("type: %d\n", sym_type);
        }
    }

    free(sh_symtab_data);
errout_with_strsymtab:
    free(sh_strsymtab_data);
errout_with_strtab:
    free(sh_strtab_data);
errout_with_shdr:
    free(section_header);
errout_with_file:
    fclose(f_elf);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        print_help();

    return parse_elf(argv[1]);
}
