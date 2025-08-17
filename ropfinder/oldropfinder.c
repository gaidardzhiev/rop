#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <capstone.h>

#define MAX_INSN_COUNT 5  // max instructions per gadget

void print_bytes(unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

// Print instructions as one gadget
void print_gadget(cs_insn *insns, size_t count, size_t base_addr) {
    printf("Gadget @ 0x%lx:\n", base_addr);
    for (size_t i = 0; i < count; i++) {
        printf("  0x%lx:\t%s\t\t%s\n", insns[i].address, insns[i].mnemonic, insns[i].op_str);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <elf-file> <arch> [max-instructions-per-gadget]\n", argv[0]);
        fprintf(stderr, "supported CPU architectures: x86, x86_64, arm, arm64\n");
        return 1;
    }

    const char *elf_file = argv[1];
    const char *arch_str = argv[2];
    int max_insn = (argc >= 4) ? atoi(argv[3]) : MAX_INSN_COUNT;
    if (max_insn <= 0)
        max_insn = MAX_INSN_COUNT;

    csh handle;
    cs_arch arch;
    cs_mode mode;

    // Select architecture and mode for Capstone based on input
    if (strcmp(arch_str, "x86") == 0) {
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
    } else if (strcmp(arch_str, "x86_64") == 0) {
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
    } else if (strcmp(arch_str, "arm") == 0) {
        arch = CS_ARCH_ARM;
        mode = CS_MODE_ARM; // 32-bit ARM mode
    } else if (strcmp(arch_str, "arm64") == 0 || strcmp(arch_str, "aarch64") == 0) {
        arch = CS_ARCH_ARM64;
        mode = CS_MODE_ARM;
    } else {
        fprintf(stderr, "Unsupported architecture: %s\n", arch_str);
        return 1;
    }

    FILE *f = fopen(elf_file, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF header\n");
        fclose(f);
        return 1;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        fclose(f);
        return 1;
    }

    int is_64bit = (ehdr.e_ident[EI_CLASS] == ELFCLASS64);
    int is_32bit = (ehdr.e_ident[EI_CLASS] == ELFCLASS32);

    if (!is_64bit && !is_32bit) {
        fprintf(stderr, "Unsupported ELF class\n");
        fclose(f);
        return 1;
    }

    size_t shdr_size = is_64bit ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr);
    uint64_t e_shoff = ehdr.e_shoff;
    uint16_t e_shnum = ehdr.e_shnum;
    uint16_t e_shstrndx = ehdr.e_shstrndx;

    if (is_32bit) {
        rewind(f);
        Elf32_Ehdr ehdr32;
        if (fread(&ehdr32, 1, sizeof(ehdr32), f) != sizeof(ehdr32)) {
            fprintf(stderr, "Failed to read ELF32 header\n");
            fclose(f);
            return 1;
        }
        e_shoff = ehdr32.e_shoff;
        e_shnum = ehdr32.e_shnum;
        e_shstrndx = ehdr32.e_shstrndx;
    }

    if (fseek(f, e_shoff, SEEK_SET) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }

    void *sh_table = malloc(shdr_size * e_shnum);
    if (!sh_table) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(f);
        return 1;
    }

    if (fread(sh_table, shdr_size, e_shnum, f) != e_shnum) {
        fprintf(stderr, "Failed to read section headers\n");
        free(sh_table);
        fclose(f);
        return 1;
    }

    uint64_t shstr_offset = 0;
    size_t shstr_size = 0;

    if (is_64bit) {
        Elf64_Shdr *shdrs = (Elf64_Shdr *)sh_table;
        shstr_offset = shdrs[e_shstrndx].sh_offset;
        shstr_size = shdrs[e_shstrndx].sh_size;
    } else {
        Elf32_Shdr *shdrs32 = (Elf32_Shdr *)sh_table;
        shstr_offset = shdrs32[e_shstrndx].sh_offset;
        shstr_size = shdrs32[e_shstrndx].sh_size;
    }

    char *sh_strtab_p = malloc(shstr_size);
    if (!sh_strtab_p) {
        fprintf(stderr, "Memory allocation failed\n");
        free(sh_table);
        fclose(f);
        return 1;
    }

    if (fseek(f, shstr_offset, SEEK_SET) != 0) {
        perror("fseek");
        free(sh_strtab_p);
        free(sh_table);
        fclose(f);
        return 1;
    }

    if (fread(sh_strtab_p, 1, shstr_size, f) != shstr_size) {
        fprintf(stderr, "Failed to read section header string table\n");
        free(sh_strtab_p);
        free(sh_table);
        fclose(f);
        return 1;
    }

    uint64_t text_offset = 0;
    uint64_t text_size = 0;
    uint64_t text_addr = 0;
    int found = 0;

    for (int i = 0; i < e_shnum; i++) {
        const char *name;
        uint64_t flags;

        if (is_64bit) {
            Elf64_Shdr *sh = &((Elf64_Shdr*)sh_table)[i];
            name = &sh_strtab_p[sh->sh_name];
            flags = sh->sh_flags;
            if ((flags & SHF_EXECINSTR) && strcmp(name, ".text") == 0) {
                text_offset = sh->sh_offset;
                text_size = sh->sh_size;
                text_addr = sh->sh_addr;
                found = 1;
                break;
            }
        } else {
            Elf32_Shdr *sh = &((Elf32_Shdr*)sh_table)[i];
            name = &sh_strtab_p[sh->sh_name];
            flags = sh->sh_flags;
            if ((flags & SHF_EXECINSTR) && strcmp(name, ".text") == 0) {
                text_offset = sh->sh_offset;
                text_size = sh->sh_size;
                text_addr = sh->sh_addr;
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        fprintf(stderr, ".text section not found\n");
        free(sh_strtab_p);
        free(sh_table);
        fclose(f);
        return 1;
    }

    unsigned char *text_data = malloc(text_size);
    if (!text_data) {
        fprintf(stderr, "Memory allocation failed\n");
        free(sh_strtab_p);
        free(sh_table);
        fclose(f);
        return 1;
    }

    if (fseek(f, text_offset, SEEK_SET) != 0) {
        perror("fseek");
        free(text_data);
        free(sh_strtab_p);
        free(sh_table);
        fclose(f);
        return 1;
    }

    if (fread(text_data, 1, text_size, f) != text_size) {
        fprintf(stderr, "Failed to read .text section data\n");
        free(text_data);
        free(sh_strtab_p);
        free(sh_table);
        fclose(f);
        return 1;
    }

    fclose(f);

    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        free(text_data);
        free(sh_strtab_p);
        free(sh_table);
        return 1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    printf("Scanning ELF .text section for ROP gadgets on architecture %s...\n", arch_str);

    cs_insn *insn;
    size_t count;

    for (size_t offset = 0; offset < text_size; offset++) {
        size_t max_bytes = text_size - offset;
        size_t max_gadget_bytes = max_insn * 15;
        size_t cur_max_bytes = max_bytes > max_gadget_bytes ? max_gadget_bytes : max_bytes;

        count = cs_disasm(handle, text_data + offset, cur_max_bytes, text_addr + offset, max_insn, &insn);
        if (count > 0) {
            for (size_t len = 1; len <= count; len++) {
                cs_insn *last = &insn[len - 1];
                int is_rop_ret = 0;

                if (arch == CS_ARCH_X86) {
                    if (strcmp(last->mnemonic, "ret") == 0)
                        is_rop_ret = 1;
                } else if (arch == CS_ARCH_ARM) {
                    if (strcmp(last->mnemonic, "bx") == 0 && strcmp(last->op_str, "lr") == 0)
                        is_rop_ret = 1;
                    else if (strcmp(last->mnemonic, "pop") == 0 && strstr(last->op_str, "pc") != NULL)
                        is_rop_ret = 1;
                    else if (strcmp(last->mnemonic, "ret") == 0)
                        is_rop_ret = 1;
                } else if (arch == CS_ARCH_ARM64) {
                    if (strcmp(last->mnemonic, "ret") == 0)
                        is_rop_ret = 1;
                }

                if (is_rop_ret) {
                    print_gadget(insn, len, insn[0].address);
                    break;
                }
            }
            cs_free(insn, count);
        }
    }

    cs_close(&handle);
    free(text_data);
    free(sh_strtab_p);
    free(sh_table);

    return 0;
}
