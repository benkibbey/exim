
/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) The Exim Maintainers 2021 */
/* Copyright (c) 2021 Ben Kibbey <bjk@luxsci.net> */
/* See the file NOTICE for conditions of use and distribution. */

#include <libpwmd.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include "../exim.h"

/* Socket arguments passed to pwmd_connect () parsed from pwmd_socket_args. */
#define ARG_MAX	8

static uschar *args[ARG_MAX];
static pwm_t *handle;

static void
free_args(uschar ** args)
{
int i;

for (i = 0; i < ARG_MAX; i++)
  {
  store_free(args[i]);
  args[i] = NULL;
  }
}

static void *
pwm_open(const uschar * filename, uschar ** errmsg)
{
gpg_error_t rc = pwmd_init();

if (rc)
  {
  *errmsg = string_sprintf("%s: error initializing libpwmd: %u: %s", __FUNCTION__, rc, gpg_strerror(rc));
  return NULL;
  }

/* pwmd_socket_args is a comma separated list of socket options. The order is
important and should be the same as specified for pwmd_connect() in the
libpwmd(3) manual. Note that not all (NULL) args are used and are for possible
future use. */
if (pwmd_socket_args)
  {
  uschar buf[PATH_MAX], *p = buf, *sp;
  int argn = 0;

  for (sp = pwmd_socket_args; sp && *sp; sp++)
    {
    while (*sp && isspace(*sp)) sp++;

    if (*sp && (*sp == ',' || !*(sp + 1)))
      {
      if (!*(sp + 1)) *p++ = *sp;
      *p = 0;

      args[argn++] = string_copy(buf);
      if (argn >= ARG_MAX) break;

      buf[0] = 0;
      p = buf;
      continue;
      }
    *p++ = *sp;
    }

  if (argn >= ARG_MAX)
    {
    *errmsg = string_sprintf ("Too many parameters to pwmd_connect() (max=%i)! Not continuing.", ARG_MAX);
    free_args(args);
    return NULL;
    }
  }

return (void *)(1);		/* Just return something non-null */
}

static void
pwm_tidy(void)
{
pwmd_close(handle);
handle = NULL;
}

static int
pwm_find(void *data, const uschar * filename, const uschar * query,
int length, uschar ** result, uschar ** errmsg, uint * do_cache,
const uschar * opts)
{
char *cmd_result;
gpg_error_t rc = 0;

/* Not used. */
data = data;
filename = filename;
length = length;
opts = opts;

if (!pwmd_file || !*pwmd_file)
  {
  *errmsg = string_sprintf("%s: required parameter pwmd_file is not set", __FUNCTION__);
  return FAIL;
  }

*do_cache = FALSE;

if (!handle)
  {
  rc = pwmd_new("exim", &handle);
  if (rc)
    {
    DEBUG(D_lookup) debug_printf("%s: ENOMEM while obtaining new handle", __FUNCTION__);
    *errmsg = string_sprintf("%s: pwmd_new(): %u: %s", __FUNCTION__, rc, gpg_strerror(rc));
    return DEFER;
    }

  rc = pwmd_setopt(handle, PWMD_OPTION_LOCK_ON_OPEN, 0);
  if (rc)
    {
    *errmsg = string_sprintf("%s: pwmd_setopt(): %u: %s", __FUNCTION__, rc, gpg_strerror(rc));
    pwmd_close(handle);
    handle = NULL;
    return FAIL;
    }

  rc = pwmd_connect(handle, (char *)pwmd_socket, args[0], args[1],
		    args[2], args[3], args[4], args[5], args[6], args[7]);
  if (rc)
    {
    *errmsg = string_sprintf("%s: pwmd_connect(): %u: %s "
			     "(arg1='%s' arg2='%s' arg3='%s' arg4='%s' "
			     "arg5='%s' arg6='%s' arg7='%s' arg8='%s')",
			     __FUNCTION__, rc, gpg_strerror(rc),
			     args[0], args[1], args[2], args[3],
			     args[4], args[5], args[6], args[7]);
    pwmd_close(handle);
    handle = NULL;
    return DEFER;
    }

  DEBUG(D_lookup) debug_printf("%s: connected to pwmd server at %s",
			       __FUNCTION__,
			       pwmd_socket ? (char *)pwmd_socket : (char *)
			       "default socket");

  rc = pwmd_setopt(handle, PWMD_OPTION_LOCK_TIMEOUT, 100);
  if (rc)
    {
    *errmsg = string_sprintf("%s: error while setting lock timeout: %u: %s", __FUNCTION__, rc, gpg_strerror(rc));
    pwmd_close(handle);
    handle = NULL;
    return DEFER;
    }
  }

do
  {
  if (gpg_err_code(rc) == GPG_ERR_CHECKSUM)
    {
    DEBUG(D_lookup) debug_printf("%s: pwmd reopening data file %s: %u: %s",
				 __FUNCTION__, (char *)pwmd_file, rc,
				 gpg_strerror(rc));
    }

  rc = pwmd_open(handle, (char *)pwmd_file, NULL, NULL);
  if (rc) break;

  DEBUG(D_lookup) debug_printf("%s: opened pwmd file: %s", __FUNCTION__, pwmd_file);
  rc = pwmd_command(handle, &cmd_result, NULL, NULL, NULL, "GET %s", query);

  /* Re-open the data file when another client has modified it (SAVE).  The
   * datafile has not been locked during pwmd_open() to prevent a stalled
   * remote connection (here) holding the lock from another client. */
  if (gpg_err_code(rc) == GPG_ERR_CHECKSUM) sleep(1);
  }
while (gpg_err_code(rc) == GPG_ERR_CHECKSUM);

if (rc)
  {
  *errmsg = string_sprintf("%s: deferring due to pwmd error %u: %s", __FUNCTION__, rc, gpg_strerror(rc));
  return DEFER;
  }
else
  {
  size_t len = strlen(cmd_result) * 2;
  uschar *escaped = store_get(len + 1, FALSE);
  uschar *e;
  char *p;

  DEBUG(D_lookup) debug_printf("%s: pwmd GET succeeded", __FUNCTION__);
  if (!escaped)
    {
    DEBUG(D_lookup) debug_printf("%s: deferring due to ENOMEM while escaping command result", __FUNCTION__);
    pwmd_free(cmd_result);
    return DEFER;
    }

  for (p = cmd_result, e = escaped; *p; p++)
    {
    switch (*p)
      {
      case '$':
      case '\\':
      *e++ = '\\';
      default:
      *e++ = *p;
      break;
      }
    }

  *e = 0;
  *result = escaped;
  *do_cache = TRUE;
  }

pwmd_free(cmd_result);
return OK;
}

static lookup_info _lookup_info = {
.name = US "pwmd",		/* lookup name */
.type = lookup_querystyle,	/* query-style lookup */
.open = pwm_open,		/* open function */
.check = NULL,			/* no check function */
.find = pwm_find,		/* find function */
.close = NULL,			/* no close function */
.tidy = pwm_tidy,		/* tidy function */
.quote = NULL,			/* no quoting function */
.version_report = NULL		/* no version reporting */
};

#ifdef DYNLOOKUP
#define pwmd_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info pwmd_lookup_module_info =
{ LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/pwmd.c */
