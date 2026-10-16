// The F-Droid build has no ultra-wideband: androidx.core.uwb depends on
// Google Play services, which this build never includes.

package org.todoke.android.radio

import android.content.Context

@Suppress("UNUSED_PARAMETER")
fun platformUwb(context: Context): Uwb? = null
