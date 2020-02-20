/*
 *  ConnMan storage unit tests storage root redefiner
 *
 *  Copyright (C) 2020 Jolla Ltd. All rights reserved.
 *  Contact: jussi.laakkonen@jolla.com
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifndef TEST_STORAGE_HELPER
#define TEST_STORAGE_HELPER

/*
 * This is done because complier otherwise warns abour redefinition of the
 * variable and redefining with compiler flags does not work. This changes
 * the storage root to much safer location for the tests.
 */
#ifdef DEFAULT_STORAGE_ROOT
	#undef DEFAULT_STORAGE_ROOT
#endif

#define DEFAULT_STORAGE_ROOT DEFAULT_TMPDIR

#endif
