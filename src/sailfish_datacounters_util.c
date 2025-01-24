/*
 *  Connection Manager
 *
 *  Copyright (C) 2016-2018 Jolla Ltd. All rights reserved.
 *  Copyright (C) 2016-2018 Slava Monich <slava.monich@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include "sailfish_datacounters.h"
 
typedef GDateTime *(*datacounters_time_change_t)(GDateTime *time, gint amount);

/*==========================================================================*
 * GDateTime manupulation functions
 *==========================================================================*/

static GDateTime *datacounters_time_add_seconds(GDateTime *t, gint sec)
{
	return g_date_time_add_seconds(t, sec);
}

static const datacounters_time_change_t datacounters_time_add_fn [] = {
	datacounters_time_add_seconds,  /* TIME_UNIT_SECOND */
	g_date_time_add_minutes,        /* TIME_UNIT_MINUTE */
	g_date_time_add_hours,          /* TIME_UNIT_HOUR */
	g_date_time_add_days,           /* TIME_UNIT_DAY */
	g_date_time_add_months,         /* TIME_UNIT_MONTH */
	g_date_time_add_years           /* TIME_UNIT_YEAR */
};

G_STATIC_ASSERT(G_N_ELEMENTS(datacounters_time_add_fn) == TIME_UNITS);

/* datacounters_time_now is redefined by unit tests */
#ifndef datacounters_time_now
GDateTime *datacounters_time_now()
{
	return g_date_time_new_now_utc();
}
#endif

/* Seconds since 1970-01-01 00:00:00 UTC */
gint64 datacounters_now()
{
	GDateTime *now = datacounters_time_now();
	gint64 t = g_date_time_to_unix(now);

	g_date_time_unref(now);
	return t;
}

GDateTime *datacounters_time_from_units(GTimeZone *tz, const guint *units)
{
	return g_date_time_new(tz, units[TIME_UNIT_YEAR],
			units[TIME_UNIT_MONTH], units[TIME_UNIT_DAY],
			units[TIME_UNIT_HOUR], units[TIME_UNIT_MINUTE],
			units[TIME_UNIT_SECOND]);

}

void datacounters_time_to_units(guint *units, GDateTime *time)
{
	gint year, month, day;

	g_date_time_get_ymd(time, &year, &month, &day);
	units[TIME_UNIT_YEAR] = year;
	units[TIME_UNIT_MONTH] = month;
	units[TIME_UNIT_DAY] = day;
	units[TIME_UNIT_HOUR] = g_date_time_get_hour(time);
	units[TIME_UNIT_MINUTE] = g_date_time_get_minute(time);
	units[TIME_UNIT_SECOND] = g_date_time_get_second(time);
}

GDateTime *datacounters_time_add(GDateTime *time, gint value,
					enum datacounter_time_unit unit)
{
	return datacounters_time_add_fn[unit](time, value);
}

GDateTime *datacounters_time_add_period(GDateTime *time,
				const struct datacounter_time_period *period)
{
	return datacounters_time_add(time, period->value, period->unit);
}

void datacounters_validate_timer(struct datacounter_timer *timer)
{
	static const guint min_value[TIME_UNIT_YEAR] = { 0, 0, 0, 1, 1 };
	static const guint max_value[TIME_UNIT_YEAR] = { 59, 59, 23, 31, 12 };
	enum datacounter_time_unit i;

	if (!timer->value) {
		timer->value = 1;
	}
	if ((int)timer->unit < (int)TIME_UNIT_SECOND ||
			timer->unit > TIME_UNIT_YEAR) {
		timer->unit = TIME_UNIT_DEFAULT;
	}
	for (i = TIME_UNIT_SECOND; i < timer->unit; i++) {
		if (timer->at[i] > max_value[i]) {
			timer->at[i] = max_value[i];
		} else if (timer->at[i] < min_value[i]) {
			timer->at[i] = min_value[i];
		}
	}

	/*
	 * The remaining ones are reset to the minimum value if they are
	 * outside of the valid range. Those are going to be ignored anyway.
	 */
	for (; i < G_N_ELEMENTS(timer->at); i++) {
		if (timer->at[i] > max_value[i] ||
			timer->at[i] < min_value[i]) {
			timer->at[i] = min_value[i];
		}
	}
}

GDateTime *datacounters_time_normalize(GDateTime *time, GTimeZone *tz,
					enum datacounter_time_unit unit)
{
	/* Seconds are always nomalized */
	static const guint min_unit[TIME_UNIT_YEAR] = { 0, 0, 0, 1, 1 };

	if (unit > TIME_UNIT_SECOND) {
		gboolean changed = FALSE;
		guint i, units[TIME_UNITS];

		datacounters_time_to_units(units, time);
		for (i=TIME_UNIT_SECOND; i<unit; i++) {
			if (units[i] != min_unit[i]) {
				units[i] = min_unit[i];
				changed = TRUE;
			}
		}

		if (changed) {
			return datacounters_time_from_units(tz, units);
		}
	}
	return g_date_time_ref(time);
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */
