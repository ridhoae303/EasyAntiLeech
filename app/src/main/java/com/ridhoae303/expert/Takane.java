// Created by ridhoae303

package com.ridhoae303.expert;

import android.content.Context;
import android.widget.Toast;

public final class Takane {
    static { System.loadLibrary("EAL"); }
    public static native boolean b(Context ctx);

    private static Context d;

    public static void c(String msg) {
        if (d != null) {
            Toast.makeText(d, msg, Toast.LENGTH_LONG).show();
        }
    }

    public static void e(Context ctx) {
        if (ctx != null) {
            d = ctx.getApplicationContext();
        }
    }
}
