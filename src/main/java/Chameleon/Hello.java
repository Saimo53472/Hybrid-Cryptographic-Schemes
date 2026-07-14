package Chameleon;

import javacard.framework.*; // Applet class

public class Hello extends Applet {
    public static void install(byte[] b, short o, byte l) {
        new Hello().register();
    }

    protected Hello() {}

    public void process(APDU apdu) {}
}