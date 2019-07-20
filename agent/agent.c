#include <android/log.h>
#include <link.h>


const char* METHOD_TO_HOOK = "open";

int callback(struct dl_phdr_info* info, size_t size, void* data);
void on_load(void) __attribute__((constructor));

void on_load(void)
{
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent started");
    int ret = dl_iterate_phdr(callback, NULL);
    __android_log_print(ANDROID_LOG_INFO, "agent", "agent finished: %d", ret);
}

int callback(struct dl_phdr_info* info, size_t size, void* data)
{
    if (NULL == info->dlpi_name) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "skipping null so");
        return 0;
    }

    __android_log_print(ANDROID_LOG_INFO, "agent", "looking at so: %s at %x", info->dlpi_name, info->dlpi_addr);
    ElfW(Addr) dynSegment = 0;
    for (uint16_t i = 0; i < info->dlpi_phnum; i++) {
        if (PT_DYNAMIC == info->dlpi_phdr[i].p_type) {
            dynSegment = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        }
    }

    if (0 == dynSegment) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "no PT_DYNAMIC segment found");
        return 0;
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "dynamic segment is at %x", dynSegment);
    ElfW(Dyn)* dynSection = (ElfW(Dyn)*)dynSegment;

    char* stringTable = 0;
    ElfW(Sym)* symbolTable = 0;
    ElfW(Rel)* relTable = 0;
    ElfW(Rela)* relaTable = 0;
    ElfW(Xword) numOfRelEntries = 0;
    ElfW(Xword) numOfRelaEntries = 0;
    for (ElfW(Xword) i = 0; dynSection[i].d_tag != DT_NULL; i++) {
        if (DT_STRTAB == dynSection[i].d_tag) {
            stringTable = (char*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_SYMTAB == dynSection[i].d_tag) {
            symbolTable = (ElfW(Sym)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_RELA == dynSection[i].d_tag) {
            relaTable = (ElfW(Rela)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_RELASZ == dynSection[i].d_tag) {
            numOfRelaEntries = dynSection[i].d_un.d_val / sizeof(ElfW(Rela));
        } else if (DT_REL == dynSection[i].d_tag) {
            relTable = (ElfW(Rel)*)(info->dlpi_addr + dynSection[i].d_un.d_ptr);
        } else if (DT_RELSZ == dynSection[i].d_tag) {
            numOfRelEntries = dynSection[i].d_un.d_val / sizeof(ElfW(Rel));
        }
    }
    __android_log_print(ANDROID_LOG_DEBUG, "agent", "stringTable: %x, symbolTable: %x, relTable: %x, relaTable: %x, numOfRelEntries: %u, numOfRelaEntries: %u",
        (ElfW(Addr))stringTable, (ElfW(Addr))symbolTable, (ElfW(Addr))relTable, (ElfW(Addr))relaTable, (ElfW(Addr))numOfRelEntries, (ElfW(Addr))numOfRelaEntries
    );
    if (0 == stringTable || 0 == symbolTable) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "could not find stringTable and symbolTable in dynamic section");
        return 0;
    }
    if (0 == relTable) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "could not find relocation table");
        return 0;
    }


    /*
    if (0 == base && PT_LOAD == info->dlpi_phdr[i].p_type) {  // the first PT_LOAD segment contains the text section and the elf header
            base = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        } else

    if (0 == base) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "no PT_LOAD segment found");
        return 0;
    }
    ElfW(Ehdr)* elfHeader = (ElfW(Ehdr)*)base;
    __android_log_print(ANDROID_LOG_INFO, "agent", "found elf header at %x: %c,%c,%c,%c", base,
        elfHeader->e_ident[0], elfHeader->e_ident[1], elfHeader->e_ident[2], elfHeader->e_ident[3]
    );
    if (ELFMAG0 != elfHeader->e_ident[0] || ELFMAG1 != elfHeader->e_ident[1] || ELFMAG2 != elfHeader->e_ident[2] || ELFMAG3 != elfHeader->e_ident[3]) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "invalid elf header");
        return 0;
    }
    uint16_t sectionNameTableIndex = elfHeader->e_shstrndx;
    ElfW(Addr) numOfSections = elfHeader->e_shnum;
    ElfW(Shdr)* sectionTable = (ElfW(Shdr)*)(base + elfHeader->e_shoff);
    char* sectionNameTable;
    if (0 == elfHeader->e_shoff || SHN_UNDEF == sectionNameTableIndex) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "no section header or section name string table: %u, %u", elfHeader->e_shoff, sectionNameTableIndex);
        return 0;
    }
    if (SHN_XINDEX == sectionNameTableIndex) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "section name string table special value");
        sectionNameTable = (char*)(base + sectionTable[sectionTable[0].sh_link].sh_offset);
    } else {
        sectionNameTable = (char*)(base + sectionTable[sectionNameTableIndex].sh_offset);
        __android_log_print(ANDROID_LOG_INFO, "agent", "%x,%x,%x",
            base, sectionTable[sectionNameTableIndex].sh_addr, sectionTable[sectionNameTableIndex].sh_offset
        );
    }
    if (0 == numOfSections) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "num of sections special value");
        numOfSections = sectionTable[0].sh_size;
    }
    __android_log_print(ANDROID_LOG_INFO, "agent", "found %u sections at %x", numOfSections, (ElfW(Addr))sectionTable);
    __android_log_print(ANDROID_LOG_INFO, "agent", "section name string table is at %x", (ElfW(Addr))sectionNameTable);
    for (ElfW(Addr) i = 0; i < numOfSections; ++i) {
        ElfW(Shdr)* section = &sectionTable[i];
        if (info->dlpi_addr != (ElfW(Addr))sectionNameTable) {
            const char* sectionName = &sectionNameTable[section->sh_name];
            __android_log_print(ANDROID_LOG_INFO, "agent", "found section %s at index %d", sectionName, i);
        }
        if (SHT_REL == section->sh_type) {
            __android_log_print(ANDROID_LOG_INFO, "agent", "found rel section at %x", section->sh_addr);
        } else if (SHT_RELA == section->sh_type) {
            __android_log_print(ANDROID_LOG_INFO, "agent", "found rela section at %x", section->sh_addr);
        }
    }
    */
    return 0;
}
