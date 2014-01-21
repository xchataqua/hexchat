/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
*/

#include <glib.h>
#include "hexchat-plugin.h"

#include "debug.c"
#include "winamp.c"
#include "spotify.c"
#include "mpc.c"

typedef struct 
{
	const char *name;
	char * (*callback) (void);
} player_t;

static hexchat_plugin *ph = NULL;
static player_t players[] = {
	{"winamp", winamp_cb},
	{"spotify", spotify_cb},
	/*{"mpc", mpc_cb},*/
	{"np_debug", debug_cb},
	{NULL, NULL},
};

static player_t*
find_player (char *name)
{
	int i;

	for (i = 0; players[i].name != NULL; ++i)
	{
		if (g_ascii_strcasecmp (name, players[i].name) == 0)
			return &players[i];
	}

	return NULL;
}

static void
print_nowplaying (player_t *player)
{
	char *song;

	/* This was intended to be more flexible but
	 * that just was not easily doable with how 
	 * the information is gathered... */
	song = player->callback ();
	if (song == NULL)
	{
		hexchat_print (ph, "NP: No song information found.");
	}
	else
	{
		char command[512];

		if (hexchat_pluginpref_get_str (ph, "command_prefix", command))
			hexchat_commandf (ph, "%s %s", command, song);
		else
			hexchat_commandf (ph, "me is now playing %s", song);

		g_free (song);
	}
}

static int
nowplaying_cb (char *word[], char *word_eol[], void *userdata)
{
	player_t *player = NULL;

	if (g_ascii_strcasecmp (word[1], "np") == 0)
	{
		if (word[2] && *word[2])
		{
			if (g_ascii_strcasecmp (word[2], "set") == 0)
			{
				if (!word[3] || !*word[3] || !word[4] || !*word[4])
					hexchat_print (ph, "NP: Valid settings are:\n    command (e.g. say)\n    default (e.g. spotify)");

				else if (g_ascii_strcasecmp (word[3], "default") == 0)
				{
					if (hexchat_pluginpref_set_str (ph, "default_player", word[4]))
						hexchat_print (ph, "NP: Default player set.");
				}
				else if (g_ascii_strcasecmp (word[3], "command") == 0)
				{
					if (hexchat_pluginpref_set_str (ph, "command_prefix", word[4]))
						hexchat_print (ph, "NP: Default command set.");
				}
			}
			else
				hexchat_command (ph, "help np");
		}
		else
		{
			char name[512];

			if (hexchat_pluginpref_get_str (ph, "default_player", name))
			{
				player = find_player (name);
				if (player != NULL)
					print_nowplaying (player);
				else
					hexchat_printf (ph, "NP: Player %s is not valid.", name);
			}
			else
			{
				hexchat_print (ph, "NP: No default player set.");
				hexchat_command (ph, "help np");
			}
		}
	}
	else /* /spotify, /winamp, etc */
	{
		player = find_player (word[1]);
		if (player != NULL)
		{
			print_nowplaying (player);
		}
	}

	return HEXCHAT_EAT_ALL;
}

int
hexchat_plugin_init (hexchat_plugin *plugin_handle,
					char **plugin_name,
					char **plugin_desc,
					char **plugin_version,
					char *arg)
{
	ph = plugin_handle;
	*plugin_name = "NowPlaying";
	*plugin_desc = "Print now playing tracks from various players";
	*plugin_version = "0.1";

	int i;

	hexchat_command (ph, "MENU ADD \"Window/Display Current Song\" \"NP\"");
	hexchat_hook_command (ph, "np", HEXCHAT_PRI_NORM, nowplaying_cb, "NP: Announces current song in default player\nNP SET: Sets various settings", NULL);

	/* Hook each players name as a command. */
	for (i = 0; players[i].name != NULL; ++i)
		hexchat_hook_command (ph, players[i].name, HEXCHAT_PRI_NORM, nowplaying_cb, NULL, NULL);

	hexchat_print (ph, "NowPlaying plugin loaded\n");

	return 1;
}

int
hexchat_plugin_deinit (void)
{
	hexchat_command (ph, "MENU DEL \"Window/Display Current Song\"");
	hexchat_print (ph, "NowPlaying plugin unloaded.\n");

	return 1;
}
