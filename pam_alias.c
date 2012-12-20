#define _POSIX_SOURCE

#include <sys/stat.h>

#include <unistd.h>
#include <stdio.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>


static const char *module_id = "pam_alias.0x2c.org";


static const char *
longoptarg(const char *arg, const char *name)
{
	if (strncmp(arg, name, strlen(name)) != 0)
		return (NULL);
	if (arg[strlen(name)] != '=')
		return (NULL);
	return (&arg[strlen(name) + 1]);
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
	int debug = 0;
	const char *aliasfn = NULL;
	enum {
		NOMATCH_IGNORE,
		NOMATCH_FAIL,
	} nomatch = NOMATCH_IGNORE;
	const char *opt;

	/* exit early if we've been through this before */
	const void *dummy;
	if (pam_get_data(pamh, module_id, &dummy) == PAM_SUCCESS)
		return (PAM_IGNORE);

	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if ((opt = longoptarg(argv[i], "file"))) {
			aliasfn = opt;
		} else if ((opt = longoptarg(argv[i], "nomatch"))) {
			if (strcmp(opt, "fail") == 0) {
				nomatch = NOMATCH_FAIL;
			} else if (strcmp(opt, "ignore") == 0) {
				nomatch = NOMATCH_IGNORE;
			} else {
				pam_syslog(pamh, LOG_ERR,
					   "invalid argument \"%s\" for nomatch option",
					   opt);
			}
		} else {
			pam_syslog(pamh, LOG_ERR,
				   "bad option \"%s\"",
				   argv[i]);
		}
	}

	if (!aliasfn) {
		pam_syslog(pamh, LOG_ERR,
			   "Alias filename not specified");
		goto fail;
	}

	FILE *aliasf;
	if (!(aliasf = fopen(aliasfn, "r"))) {
		pam_syslog(pamh, LOG_ERR,
			   "Error opening %s",
			   aliasfn);
		goto fail;
	}

	struct stat st;
	if (fstat(fileno(aliasf), &st) < 0) {
		pam_syslog(pamh, LOG_ERR,
			   "Cannot stat %s",
			   aliasfn);
		goto fail;
	}

	if (st.st_mode & S_IWOTH || !S_ISREG(st.st_mode)) {
		pam_syslog(pamh, LOG_ALERT,
			   "Insecure permissions on %s",
			   aliasfn);
		goto fail;
	}

	char *user;
	int rv;
	if ((rv = pam_get_item(pamh, PAM_USER, (void *)&user)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR,
			   "Cannot obtain current pam user: %s",
			   pam_strerror(pamh, rv));
		goto fail;
	}

	int lineno = 0;
	char line[256];
	while (fgets(line, sizeof(line), aliasf) != NULL) {
		char *saveptr;

		lineno++;

		if (line[strlen(line) - 1] != '\n' && !feof(aliasf)) {
			pam_syslog(pamh, LOG_ALERT,
				   "overlong line at %s:%d",
				   aliasfn, lineno);
			/* skip over rest of line */
			while (fgets(line, sizeof(line), aliasf) != NULL) {
				if (line[strlen(line) - 1] == '\n')
					break;
			}
			continue;
		}

		char *from = strtok_r(line, " \t\n", &saveptr);
		char *to = strtok_r(line, " \t\n", &saveptr);

		if (!from)
			continue;

		if (from[0] == '#') {
			if (debug)
				pam_syslog(pamh, LOG_DEBUG,
					   "skipping comment line at %s:%d",
					   aliasfn, lineno);
			continue;
		}

		if (!to) {
			pam_syslog(pamh, LOG_ALERT,
				   "malformed alias entry at %s:%d",
				   aliasfn, lineno);
			continue;
		}

		if (debug)
			pam_syslog(pamh, LOG_DEBUG,
				   "alias entry: \"%s\" -> \"%s\"",
				   from, to);

		if (strcmp(from, user) == 0) {
			pam_syslog(pamh, LOG_INFO,
				   "matched user alias \"%s\" to \"%s\"",
				   from, to);
			if (pam_set_item(pamh, PAM_USER, to) != PAM_SUCCESS) {
				pam_syslog(pamh, LOG_ERR,
					   "Cannot set pam user to \"%s\": %s",
					   to,
					   pam_strerror(pamh, rv));
				goto fail;
			}

			/**
			 * Set a flag so that we know that we've done
			 * a pass.
			 *
			 * If this fails, we can't do anything about
			 * it.
			 */

			pam_set_data(pamh, module_id, (void *)1, NULL);

			/* success changing the user */
			return (PAM_IGNORE);
		}
	}

	switch (nomatch) {
	case NOMATCH_IGNORE:
		return (PAM_IGNORE);
	case NOMATCH_FAIL:
		return (PAM_AUTH_ERR);
	}

fail:
	return (PAM_SERVICE_ERR);
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	       int argc, const char **argv)
{
	return (PAM_SUCCESS);
}

int
pam_sm_acct_mgmgt(pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
	return (pam_sm_authenticate(pamh, flags, argc, argv));
}
