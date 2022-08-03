/*	$NetBSD: print-http.c $ 	*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//#ifndef lint
//static const char rcsid[] _U_ =
//     "@(#) $Header: /tcpdump/master/tcpdump/print-telnet.c,v 1.24 2003-12-29 11:05:10 hannes Exp $";
//#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"

static inline unsigned is_space(char c)
{
	return (c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

static inline unsigned is_blank(char c)
{
	return (c == ' ' || c == '\t');
}

void http_print(const u_char *sp, u_int length)
{
	static const char null_host[] = "(null)";

	if (length < 10)
		return;

	if (strncmp(sp, "GET /", 5) == 0 || strncmp(sp, "POST /", 6) == 0) {
		const char *req_start = sp, *req_end = sp + length;
		const char *ln_start, *ln_end;
		const char *host_start = NULL, *uri_start = NULL,
			*uri_end, *method_start = NULL, *rf_start = NULL, *ua_start = NULL;
		size_t uri_len = 0, host_len = 0, method_len = 0, rf_len = 0, ua_len = 0;

		/* Parse status line */
		ln_start = req_start;
		if ((ln_end = (const char *)memchr(ln_start, '\n', req_end - ln_start)) == NULL)
			return;
		method_start = ln_start;
		/* Pick out URL */
		if ((uri_start = (const char *)memchr(ln_start, ' ', ln_end - ln_start)) == NULL)
			return;
		while (uri_start < ln_end && *uri_start == ' ') {
			method_len = uri_start - method_start;
			uri_start++;
		}
		if ((uri_end = (const char *)memchr(uri_start, ' ', ln_end - uri_start)) == NULL)
			return;
		uri_len = uri_end - uri_start;

		/* Parse each header line */
		for (ln_start = ln_end + 1; ln_start < req_end &&
				(ln_end = (const char *)memchr(ln_start, '\n', req_end - ln_start));
			ln_start = ln_end + 1) {
			const char *nm_start, *nm_end;
			const char *val_start, *val_end;
			size_t nm_len, val_len;

			/* An empty line indicates header analysis is over */
			if ((ln_end == ln_start) || (ln_end == ln_start + 1 && *ln_start == '\r')) {
				ln_start = ln_end + 1;
				break;
			}

			/* Option name:: */
			nm_start = ln_start;
			if ((nm_end = (const char *)memchr(nm_start, ':', ln_end - nm_start)) == NULL)
				continue;
			nm_len = nm_end - nm_start;
			/* Option value:: */
			for (val_start = nm_end + 1; val_start < ln_end && is_blank(*val_start); val_start++);
			for (val_end = ln_end; (val_end > val_start) && is_space(*(val_end - 1)); val_end--);
			if ((val_len = val_end - val_start) == 0)
				continue;

			if (nm_len == 4 && strncasecmp(nm_start, "Host", 4) == 0) {
				const char *sep;
				/* Remember Host value */
				host_start = val_start;
				host_len = val_len;
				//if((sep = memchr(host_start, ':', host_len)))
				//	host_len = (size_t)(sep - host_start);
			} else if (nm_len == 7 && strncasecmp(nm_start, "Referer", 7) == 0) {
				rf_start = val_start;
				rf_len = val_len;
			} else if(nm_len == 10 && strncasecmp(nm_start, "User-Agent", 10) == 0) {
				ua_start = val_start;
				ua_len = val_len;
			}
		} /* for(ln_start = ln_end + 1;... */

		/* Check hostname validity */
		if (host_start == NULL) {
			host_start = null_host;
			host_len = strlen(null_host);
		}

		/* Print the whole URL if it has one. */
		do {
			char the_method[64] = "---", whole_url[4096] = "", *filter;

			if (host_len + uri_len >= sizeof(whole_url))
				break;

			if (method_len > 0) {
				memcpy(the_method, method_start, method_len);
				the_method[method_len] = '\0';
			}

			memcpy(whole_url, host_start, host_len);
			memcpy(whole_url + host_len, uri_start, uri_len);
			whole_url[host_len + uri_len] = '\0';

			/* If filter specified, check it */
			if ((filter = getenv("FILTER"))) {
				if (!strstr(whole_url, filter))
					break;
			}

			fprintf(stderr, "%-4s http://%s\n", the_method, whole_url);
			//fflush(stderr);
		} while (0);
	} else if (strncmp(sp, "HTTP/1.", 7) == 0) {
		const char *resp = (const char *)sp, *resp_end = sp + length;
		const char *ln_start, *ln_end;
		const char *sc_start, *sc_end;
		const char *sd_start, *sd_end;
		size_t sc_len, sd_len;
		char stcode_buf[10];
		int stcode = 0;
		const char *loc_start = NULL;
		size_t loc_len = 0;

		/* Only in verbose mode do we print response status. */
		if (!vflag)
			return;

		/* Parse status line */
		ln_start = resp;
		if ((ln_end = (const char *)memchr(ln_start, '\n', resp_end - ln_start)) == NULL)
			return;

		/* Pick out status code number */
		if ((sc_start = (const char *)memchr(ln_start, ' ', ln_end - ln_start)) == NULL)
			return;
		while (sc_start < ln_end && *sc_start == ' ')
			sc_start++;
		if ((sc_end = (const char *)memchr(sc_start, ' ', ln_end - sc_start)) == NULL)
			return;
		sc_len = sc_end - sc_start;

		/* Pick out status description */
		sd_start = sc_end + 1;
		while (sd_start < ln_end && *sd_start == ' ')
			sd_start++;
		for (sd_end = ln_end; sd_end > sd_start && is_space(*(sd_end - 1)); sd_end--);
		sd_len = sd_end - sd_start;

		/* Convert status to numeric for validition. */
		if (sc_len >= 10)
			return;
		memcpy(stcode_buf, sc_start, sc_len);
		stcode_buf[sc_len] = '\n';
		if (sscanf(sc_start, "%d", &stcode) != 1)
			return;

		/* Parse each header line */
		for (ln_start = ln_end + 1; ln_start < resp_end &&
				(ln_end = (const char *)memchr(ln_start, '\n', resp_end - ln_start));
			ln_start = ln_end + 1) {
			const char *nm_start, *nm_end;
			const char *val_start, *val_end;
			size_t nm_len, val_len;

			/* An empty line indicates header analysis is over */
			if (ln_end == ln_start || (ln_end == ln_start + 1 && *ln_start == '\r')) {
				ln_start = ln_end + 1;
				break;
			}
			/* Option name:: */
			nm_start = ln_start;
			if ((nm_end = (const char *)memchr(nm_start, ':', ln_end - nm_start)) == NULL) 
				continue;
			nm_len = nm_end - nm_start;
			/* Option value:: */
			for (val_start = nm_end + 1; val_start < ln_end && is_blank(*val_start); val_start++);
			for (val_end = ln_end; val_end > val_start && is_space(*(val_end - 1)); val_end--);
			if ((val_len = val_end - val_start) == 0)
				continue;

			/**
			 * Prepared arguments: mn_start, mn_len, val_start, val_len.
			 */

			/* Check each HTTP response option */
			if (nm_len == 6 && strncasecmp(nm_start, "Location", 6) == 0) {
				loc_start = val_start;
				loc_len = val_len;
			}

		} /* for(ln_start = ln_end + 1 ... */

		/* Print the response status. */
		fprintf(stderr, "[%d ", stcode);
		fwrite(sd_start, 1, sd_len, stderr);
		fputs("]\n", stderr);
		//fflush(stderr);
	}

}

