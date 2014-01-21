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
#include "hexchat-plugin.h"

extern hexchat_plugin *ph;

static BOOL CALLBACK 
debug_enum_func (HWND hwnd, LPARAM param)
{
	char window_text[1024];
	char window_class[1024];
	memset (window_text, 0, sizeof(window_text));
	memset (window_class, 0, sizeof(window_class));

	if (GetWindowTextA (hwnd, window_text, sizeof(window_text))
		&& GetClassNameA (hwnd, window_class, sizeof(window_class)))
	{
		if (strcmp (window_class, "IME") && strcmp (window_class, "MSCTFIME UI"))
			hexchat_printf (ph, "Class: %s | Title: %s", window_class, window_text);
	}

	return 1;
}

static char *
debug_cb (void)
{
	EnumWindows (debug_enum_func, 0);
	return NULL;
}
