/* Name of package */
#cmakedefine PACKAGE "${APPLICATION_NAME}"

/* Version number of package */
#cmakedefine VERSION "${APPLICATION_VERSION}"

#cmakedefine LOCALEDIR "${LOCALE_INSTALL_DIR}"
#cmakedefine DATADIR "${DATADIR}"
#cmakedefine LIBDIR "${LIBDIR}"
#cmakedefine PLUGINDIR "${PLUGINDIR}"
#cmakedefine SYSCONFDIR "${SYSCONFDIR}"
#cmakedefine BINARYDIR "${BINARYDIR}"
#cmakedefine SOURCEDIR "${SOURCEDIR}"

/************************** HEADER FILES *************************/

#cmakedefine HAVE_SYS_TYPES_H 1
#cmakedefine HAVE_SYS_SYSCALL_H 1
#cmakedefine HAVE_SYSCALL_H 1
#cmakedefine HAVE_UNISTD_H 1
#cmakedefine HAVE_GRP_H 1

/*************************** FUNCTIONS ***************************/

/* Define to 1 if you have the `seteuid' function. */
#cmakedefine HAVE_SETEUID 1

/* Define to 1 if you have the `setreuid' function. */
#cmakedefine HAVE_SETREUID 1

/* Define to 1 if you have the `setresuid' function. */
#cmakedefine HAVE_SETREUID 1

/* Define to 1 if you have the `setegid' function. */
#cmakedefine HAVE_SETEGID 1

/* Define to 1 if you have the `setregid' function. */
#cmakedefine HAVE_SETREGID 1

/* Define to 1 if you have the `setresgid' function. */
#cmakedefine HAVE_SETREGID 1

/* Define to 1 if you have the `syscall' function. */
#cmakedefine HAVE_SYSCALL 1

/*************************** LIBRARIES ***************************/

/**************************** OPTIONS ****************************/

#cmakedefine HAVE_LINUX_32BIT_SYSCALLS 1

#cmakedefine HAVE_GCC_THREAD_LOCAL_STORAGE 1

/*************************** ENDIAN *****************************/

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN 1
