#include <string_view>
#include <vector>

#include <bionic/linker.h>


void on_load() __attribute__((constructor));
int relocationTableHook(struct dl_phdr_info* info, size_t size, void* data);
ElfW(Addr) align(ElfW(Addr) addr, int pagesize);
bool changeProtection(ElfW(Addr) addr, int pagesize, size_t len, int protection);

struct HookInfo
{
    std::string_view symbol;
    ElfW(Word) relocType;
    ElfW(Addr) hook;
    ElfW(Addr) original;
    int pagesize;
    size_t numOfHooks;
};

class RelocTableHook
{
    public:
        RelocTableHook(const dl_phdr_info* moduleInfo);
        bool shouldIgnoreModule(const std::vector<std::string_view>& modulesToIgnore);
        bool parseDynamicSection();
        size_t performHook(const HookInfo* hookInfo);
    private:
        std::string_view m_moduleName;
        ElfW(Addr) m_loadBias;
        const dl_phdr_info* m_phdrInfo;

        const char* m_stringTable;
        const ElfW(Sym)* m_symbolTable;
        const rel_t* m_pltRel;
        ElfW(Xword) m_numOfPltRelEntries;
};
