package com.test;

public class Test {

    public static void main(String[] args) {
        short[] mul = new short[4];

        U32.mul64(
            (short)0xFFFF, (short)0xFFFF,
            (short)0xFFFF, (short)0xFFFF,
            mul, (short)0);

        System.out.printf(
    "hiPart=%04X %04X  loPart=%04X %04X\n",
    mul[1] & 0xFFFF,
    mul[0] & 0xFFFF,
    mul[3] & 0xFFFF,
    mul[2] & 0xFFFF);
    }
}