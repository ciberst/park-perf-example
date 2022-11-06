#ifndef FLAGS_H
#define FLAGS_H

#define BUILDFLAG_CAT_INDIRECT(a, b) a##b
#define BUILDFLAG_CAT(a, b) BUILDFLAG_CAT_INDIRECT(a, b)
#define BUILDFLAG(flag) (BUILDFLAG_CAT(BUILDFLAG_INTERNAL_, flag)())

#if defined(_WIN32)
#define BUILDFLAG_INTERNAL_IS_WIN() (1)
#else
#define BUILDFLAG_INTERNAL_IS_WIN() (0)
#endif

#if defined(__linux__)
#define BUILDFLAG_INTERNAL_IS_LINUX() (1)
#else
#define BUILDFLAG_INTERNAL_IS_LINUX() (0)
#endif

#if defined(__APPLE__)
#define BUILDFLAG_INTERNAL_IS_MACOS() (1)
#else
#define BUILDFLAG_INTERNAL_IS_MACOS() (0)
#endif

#endif /* FLAGS_H */
