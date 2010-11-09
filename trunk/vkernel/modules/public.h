#pragma once

typedef enum {
   Opk_Bool,
   Opk_Int,
   Opk_Str
} OptKind;

struct ModOpt {
   char key[MAX_OPT_KEY_LEN];
   int (*setOptCb)(int optId, const char *optArg);
   OptKind kind;
   char defValue[MAX_OPT_VALUE_LEN];
   char helpStr[256];
};

#define MAX_MODNAME_LEN 32
struct ModDesc {
   char name[MAX_MODNAME_LEN];
   char desc[256];
   struct ModOpt *optA;
   int (*doneFn)(const int argc, char **argv); 
   struct ModDesc **depA;
   struct ModDesc **confA;
   int isLoaded;
};

#define MODULE_VAR(m_name) __module_##m_name
#define MODULE_PTR(m_name) ({ \
      extern struct ModDesc MODULE_VAR(m_name);  \
      &MODULE_VAR(m_name); \
   }) \

/* Alignment issues prevent us from storing the entire module descriptor
 * in the .moddesc section, so we store pointers instead. */
#define MODULE_DESC(m_sec, m_name, m_desc, m_depA, m_confA, m_optA, m_doneFn) \
   struct ModDesc MODULE_VAR(m_name) = { \
         .name = #m_name, \
         .desc = m_desc, \
         .optA = m_optA, \
         .doneFn = m_doneFn, \
         .depA = m_depA, \
         .confA = m_confA, \
         .isLoaded = 0, \
      }; \
   static struct ModDesc * __ptr_module_##m_name __attribute_used__ \
      __attribute__((__section__(m_sec))) = &MODULE_VAR(m_name);

#define MODULE_BASIC(m_name, m_desc, m_depA, m_confA, m_optA, m_doneFn) \
   MODULE_DESC(".mod_desc_basic", m_name, m_desc, m_depA, m_confA, m_optA, m_doneFn)

#define MODULE_ADVANCED(m_name, m_desc, m_optA, m_doneFn) \
   MODULE_DESC(".mod_desc_advanced", m_name, m_desc, m_optA, m_donefn)

#define MODULE_ANALYSIS(m_name, m_desc, m_optA, m_doneFn) \
   MODULE_DESC(".mod_desc_analysis", m_name, m_desc, m_optA, m_doneFn)


extern struct ModDesc * __mod_desc_start[], * __mod_desc_end[];
extern struct ModDesc * __modbasic_desc_start[], * __modbasic_desc_end[];
extern struct ModDesc * __modadv_desc_start[], * __modadv_desc_end[];
extern struct ModDesc * __modanalysis_desc_start[], * __modanalysis_desc_end[];

static INLINE struct ModDesc *
Module_Lookup(const char *name)
{
   struct ModDesc ** modPP;

   for (modPP = __mod_desc_start; modPP < __mod_desc_end; modPP++) {
      if (strcmp(name, (*modPP)->name) == 0) {
         return *modPP;
      }
   }

   return NULL;
}

static INLINE int
Module_IsLoaded(struct ModDesc *modP)
{
   return modP->isLoaded;
}
