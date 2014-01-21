/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "windows.h"
#include <glib.h>

static char *
winamp_cb (void)
{
	HWND hWnd = FindWindowA ("Winamp v1.x", NULL);
	if (hWnd != NULL)
	{
		char window_text[1024];
		memset (window_text, 0, sizeof(window_text));

		if (GetWindowTextA (hWnd, window_text, sizeof(window_text)))
		{
			char *str = window_text;
			char *p, *ret;

			/* Nothing playing. */
			if (strchr (str, '-') == NULL)
				return NULL;

			/* May be prefixed with track num. TODO improve. */
			p = strchr (str, '.');
			if (p != NULL)
				str = p + 2;

			/* Remove - Winamp suffix */
			if (g_str_has_suffix (str, " - Winamp"))
				ret = g_strndup (str, strlen (str) - 9);
			else
				ret = g_strdup (str);

			return ret;
		}
	}
	return NULL;
}
