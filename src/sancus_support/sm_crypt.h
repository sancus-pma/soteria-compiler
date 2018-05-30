#ifndef _SM_CRYPT_H
#define _SM_CRYPT_H

#include "sm_support.h"

struct SancusCryptModule
{
    sm_id id;
    vendor_id vendor_id;
    const char* name;
    void* public_start;
    void* public_end;
    void* secret_start;
    void* secret_end;
    void* public_start_crypt;
    void* public_end_crypt;
};

#define __PSC(name) __spm_##name##_public_start_crypt
#define __PEC(name) __spm_##name##_public_end_crypt

#define DECLARE_CRYPT_SM(name, vendor_id)                       \
    extern char __PS(name), __PE(name), __SS(name), __SE(name); \
    extern char __PSC(name), __PEC(name);                       \
    struct SancusCryptModule name = {0, vendor_id, #name,       \
                                     &__PS(name), &__PE(name),  \
                                     &__SS(name), &__SE(name),  \
                                     &__PSC(name), &__PEC(name)}

#endif /* _SM_CRYPT */
