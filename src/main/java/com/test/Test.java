package com.test;

import javacard.framework.*;

public class Test extends Applet {

    protected Test() {}

    public static void install(byte[] b, short o, byte l) {
        new Test().register();
    }

    private static short foo() {
        int x = 1;
        int y = x + 1;
        return (short)y;
    }

    public void process(APDU apdu) {}
}