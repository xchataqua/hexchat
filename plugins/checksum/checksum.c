/* HexChat
 * Copyright (c) 2010-2012 Berke Viktor.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>

#include "hexchat-plugin.h"

#define BUFSIZE 32768
#define OUTPUT_BUFSIZE 65
#define DEFAULT_LIMIT 256									/* default size is 256 MiB */
#define SHA256_DIGEST_LENGTH 32

static hexchat_plugin *ph;									/* plugin handle */
static char name[] = "Checksum";
static char desc[] = "Calculate checksum for DCC file transfers";
static char version[] = "4.0";

static void
sha256_hash_string (guint8 digest[], gsize digest_len, char outputBuffer[OUTPUT_BUFSIZE])
{
	int i;
	for (i = 0; i < digest_len; i++)
	{
		g_snprintf (outputBuffer + (i * 2), OUTPUT_BUFSIZE, "%02x", digest[i]);
	}
	outputBuffer[64] = 0;
}


/**
 * Calculates the sha256 of a full path to a file.
 * 
 * Returns: %TRUE on success
 *
 */
static gboolean
sha256_file (char *path, char outputBuffer[OUTPUT_BUFSIZE])
{
	unsigned char *buffer;
	guint8 digest[SHA256_DIGEST_LENGTH];
	gsize digest_len = sizeof(digest);
	gsize bytesRead;
	GChecksum *checksum;

	FILE *file = fopen (path, "rb");
	if (!file)
	{
		return FALSE;
	}

	buffer = malloc (BUFSIZE);
	bytesRead = 0;

	if (!buffer)
	{
		fclose (file);
		return FALSE;
	}

	checksum = g_checksum_new (G_CHECKSUM_SHA256);

	while ((bytesRead = fread (buffer, 1, BUFSIZE, file)))
	{
		g_checksum_update (checksum, buffer, bytesRead);
	}

	g_checksum_get_digest (checksum, digest, &digest_len);
	sha256_hash_string (digest, digest_len, outputBuffer);

	g_checksum_free (checksum);
	fclose (file);
	free (buffer);

	return TRUE;
}

static void
set_limit (char* size)
{
	int buffer = atoi (size);

	if (buffer > 0 && buffer < G_MAXINT)
	{
		if (hexchat_pluginpref_set_int (ph, "limit", buffer))
		{
			hexchat_printf (ph, "File size limit has successfully been set to: %d MiB\n", buffer);
		}
		else
		{
			hexchat_printf (ph, "File access error while saving!\n");
		}
	}
	else
	{
		hexchat_printf (ph, "Invalid input!\n");
	}
}

static int
get_limit ()
{
	int size = hexchat_pluginpref_get_int (ph, "limit");

	if (size <= -1 || size >= G_MAXINT)
	{
		return DEFAULT_LIMIT;
	}
	else
	{
		return size;
	}
}


/**
 * Returns: %TRUE if file is below limit
 *          %FALSE if above limit
 */
static gboolean
test_file_size (gchar *file_path)
{
	GFileInfo *file_info = NULL;
	GFile *file = NULL;
	gboolean ret = FALSE;

	file = g_file_new_for_path (file_path);
	file_info = g_file_query_info (file, G_FILE_ATTRIBUTE_STANDARD_SIZE,
									G_FILE_QUERY_INFO_NONE, NULL, NULL);
	if (file_info)
	{
		if (g_file_info_get_size (file_info) <= (unsigned long long) get_limit () * 1048576)
			ret = TRUE;

		g_object_unref (file_info);
	}
	else
	{
		hexchat_printf (ph, "Checksum: Error accessing %s.", file_path);
	}

	g_object_unref (file);
	return ret;
}

static int
dccrecv_cb (char *word[], void *userdata)
{
	char sum[OUTPUT_BUFSIZE];											/* buffer for checksum */
	const char *file;
	char *cfile;

	if (hexchat_get_prefs (ph, "dcc_completed_dir", &file, NULL) == 1 && file[0] != 0)
	{
		cfile = g_strconcat (file, G_DIR_SEPARATOR_S, word[1], NULL);
	}
	else
	{
		cfile = g_strdup(word[2]);
	}

	if (test_file_size (cfile))
	{
		if (sha256_file (cfile, sum))
		{
			/* try to print the checksum in the privmsg tab of the sender */
			hexchat_set_context (ph, hexchat_find_context (ph, NULL, word[3]));
			hexchat_printf (ph, "SHA-256 checksum for %s (local):  %s", word[1], sum);
		}
	}
	else
	{
		hexchat_set_context (ph, hexchat_find_context (ph, NULL, word[3]));
		hexchat_printf (ph, "SHA-256 checksum for %s (local):  (size limit reached, no checksum calculated, you can increase it with /CHECKSUM SET",
						word[1]);
	}

	g_free (cfile);
	return HEXCHAT_EAT_NONE;
}

static int
dccoffer_cb (char *word[], void *userdata)
{
	char sum[OUTPUT_BUFSIZE];

	/* word[3] is the full filename */
	if (test_file_size (word[3]))
	{
		if (sha256_file (word[3], sum))
		{
			hexchat_commandf (ph, "quote PRIVMSG %s :SHA-256 checksum for %s (remote): %s",
							word[2], word[1], sum);
		}
	}
	else
	{
		hexchat_printf (ph, "SHA-256 checksum for %s (remote): (size limit reached, no checksum calculated)",
							word[1]);
	}

	return HEXCHAT_EAT_NONE;
}

static int
checksum (char *word[], char *word_eol[], void *userdata)
{
	if (!g_ascii_strcasecmp ("GET", word[2]))
	{
		hexchat_printf (ph, "File size limit for checksums: %d MiB", get_limit ());
	}
	else if (!g_ascii_strcasecmp ("SET", word[2]))
	{
		set_limit (word[3]);
	}
	else
	{
		hexchat_printf (ph, "Usage: /CHECKSUM GET|SET\n");
		hexchat_printf (ph, "  GET - print the maximum file size (in MiB) to be hashed\n");
		hexchat_printf (ph, "  SET <filesize> - set the maximum file size (in MiB) to be hashed\n");
	}

	return HEXCHAT_EAT_NONE;
}

int
hexchat_plugin_init (hexchat_plugin *plugin_handle, char **plugin_name, char **plugin_desc, char **plugin_version, char *arg)
{
	ph = plugin_handle;

	*plugin_name = name;
	*plugin_desc = desc;
	*plugin_version = version;

	/* this is required for the very first run */
	if (hexchat_pluginpref_get_int (ph, "limit") == -1)
	{
		hexchat_pluginpref_set_int (ph, "limit", DEFAULT_LIMIT);
	}

	hexchat_hook_command (ph, "CHECKSUM", HEXCHAT_PRI_NORM, checksum, "Usage: /CHECKSUM GET|SET", 0);
	hexchat_hook_print (ph, "DCC RECV Complete", HEXCHAT_PRI_NORM, dccrecv_cb, NULL);
	hexchat_hook_print (ph, "DCC Offer", HEXCHAT_PRI_NORM, dccoffer_cb, NULL);

	hexchat_printf (ph, "%s plugin loaded\n", name);
	return 1;
}

int
hexchat_plugin_deinit (void)
{
	hexchat_printf (ph, "%s plugin unloaded\n", name);
	return 1;
}
