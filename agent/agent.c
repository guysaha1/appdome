#define _GNU_SOURCE
#include <android/log.h>
#include <link.h>
#include <dlfcn.h>


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
    __android_log_print(ANDROID_LOG_INFO, "agent", "looking at so: %s at %d", info->dlpi_name, info->dlpi_addr);
    ElfW(Ehdr)* elfHeader = (ElfW(Ehdr)*)info->dlpi_addr;
    uint32_t sectionNameTableIndex = elfHeader->e_shstrndx;
    ElfW(Addr) numOfSections = elfHeader->e_shnum;
    ElfW(Shdr)* sectionTable = (ElfW(Shdr)*)(info->dlpi_addr + elfHeader->e_shoff);
    if (0 == elfHeader->e_shoff || SHN_UNDEF == sectionNameTableIndex) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "no section header or section name string table: %d, %d", elfHeader->e_shoff, sectionNameTableIndex);
        return 0;
    }
    if (SHN_XINDEX == sectionNameTableIndex) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "section name string table special value");
        sectionNameTableIndex = sectionTable[0].sh_link;
    }
    if (0 == numOfSections) {
        __android_log_print(ANDROID_LOG_INFO, "agent", "num of sections special value");
        numOfSections = sectionTable[0].sh_size;
    }
    char* sectionNameTable = (char*)(sectionTable[sectionNameTableIndex].sh_addr); // maybe add info->dlpi_addr
    for (ElfW(Addr) i = 0; i < numOfSections; ++i) {
        ElfW(Shdr)* section = &sectionTable[i];
        const char* sectionName = &sectionNameTable[section->sh_name];
        __android_log_print(ANDROID_LOG_INFO, "agent", "found section %s at index %d", sectionName, i);
    }
    return 0;
}
