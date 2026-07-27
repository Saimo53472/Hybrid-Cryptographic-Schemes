// package com.test;

// public class Test {

//     public static void main(String[] args) {

//         U32 r = new U32();

//         U32.mul16((short)1, (short)1, r);
//         System.out.println("1*1      : hi=" + r.hi + " lo=" + r.lo);

//         U32.mul16((short)256, (short)256, r);
//         System.out.println("256*256  : hi=" + r.hi + " lo=" + r.lo);

//         U32.mul16((short)0, (short)12345, r);
//         System.out.println("0*12345  : hi=" + r.hi + " lo=" + r.lo);

//         U32.mul16((short)-1, (short)1, r);
//         System.out.println("FFFF*1   : hi=" + r.hi + " lo=" + r.lo);

//         U32.mul16((short)-1, (short)-1, r);
//         System.out.println("FFFF^2   : hi=" + r.hi + " lo=" + r.lo);
//     }
// }