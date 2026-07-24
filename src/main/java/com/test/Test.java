package com.test;

import javacard.framework.*;

public class Test extends Applet {

    protected Test() {}

    public static void install(byte[] b, short o, byte l) {
        new Test().register();
    }

    private static short foo() {
        short a = 1234;
        short b = 5678;
        short p1 = (short)(a * b);
        short p = (short)((short)(a * b) >>> 8);
        return p;
    }

    public void process(APDU apdu) {}
}