#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([polypseud], [1.0])
AC_CONFIG_SRCDIR([src/polypseud.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux])
LT_INIT
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h stdio.h assert.h])

# Check for OpenSSL
AC_CHECK_LIB(crypto, BN_new)
AC_CHECK_HEADERS([openssl/bio.h openssl/evp.h openssl/buffer.h openssl/ec.h openssl/bn.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC

AC_OUTPUT(Makefile src/Makefile)
