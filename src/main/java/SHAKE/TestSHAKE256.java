package SHAKE;

/**
 * Simple test runner. If BouncyCastle is available on the classpath, compare outputs.
 *
 * To compile and run (example):
 *   javac -cp bcprov-jdk15on-*.jar sha3ref/*.java
 *   java -cp .:bcprov-jdk15on-*.jar sha3ref.TestSHAKE256
 *
 * If you don't have BouncyCastle, the test still runs and prints our outputs.
 */
public class TestSHAKE256
{
    public static void main(String[] args) throws Exception
    {
        byte[] empty = new byte[0];

        // Request 4 words (4 * 8 = 32 bytes)
        long[] myWords = SHAKE256IntPair.shake256w(empty, 0, 0, 4);

        System.out.println("Our SHAKE256w(empty) first 4 words:");
        for (int i = 0; i < myWords.length; i++)
        {
            System.out.printf("word[%d] = 0x%016X%n", i, myWords[i]);
        }

        // Test SHAKE256x4 interleaved
        int totalWords = 8; // will produce 8 words interleaved across 4 instances
        long[] myX4 = SHAKE256IntPair.shake256x4_interleaved(empty, 0, 0, totalWords);
        System.out.println("Our SHAKE256x4_interleaved(empty) first " + totalWords + " words:");
        for (int i = 0; i < myX4.length; i++)
        {
            System.out.printf("x4[%d] = 0x%016X%n", i, myX4[i]);
        }

        // If BouncyCastle is present, compare a byte-level SHAKE256 output
        try
        {
            Class<?> cl = Class.forName("org.bouncycastle.crypto.digests.SHAKEDigest");
            System.out.println("BouncyCastle found; comparing byte outputs...");

            // create BC SHAKE256, produce 32 bytes of output for empty input
            Object bc = cl.getConstructor(int.class).newInstance(256); // fixedOutputLength param in BC class is often 256 for SHAKE256
            java.lang.reflect.Method update = cl.getMethod("update", byte.class);
            java.lang.reflect.Method doOutput = cl.getMethod("doOutput", byte[].class, int.class, int.class);
            java.lang.reflect.Method doFinal = cl.getMethod("doFinal", byte[].class, int.class, int.class);

            // BC SHAKEDigest has 'update(byte)' or 'update(byte[], int, int)'. We call no update for empty input.
            byte[] outBuf = new byte[32];
            doOutput.invoke(bc, outBuf, 0, outBuf.length);

            // convert BC output to words
            long[] bcWords = new long[4];
            for (int i = 0; i < 4; i++)
            {
                int bo = i * 8;
                long lo = ((long)outBuf[bo] & 0xFFL)
                        | (((long)outBuf[bo + 1] & 0xFFL) << 8)
                        | (((long)outBuf[bo + 2] & 0xFFL) << 16)
                        | (((long)outBuf[bo + 3] & 0xFFL) << 24);
                long hi = ((long)outBuf[bo + 4] & 0xFFL)
                        | (((long)outBuf[bo + 5] & 0xFFL) << 8)
                        | (((long)outBuf[bo + 6] & 0xFFL) << 16)
                        | (((long)outBuf[bo + 7] & 0xFFL) << 24);
                bcWords[i] = (hi << 32) | (lo & 0xFFFFFFFFL);
            }

            System.out.println("BouncyCastle SHAKE256(empty) first 4 words:");
            for (int i = 0; i < bcWords.length; i++)
            {
                System.out.printf("bc word[%d] = 0x%016X%n", i, bcWords[i]);
            }

            // Compare our words with BC words (first 4)
            boolean ok = true;
            for (int i = 0; i < 4; i++)
            {
                if (myWords[i] != bcWords[i])
                {
                    ok = false;
                    System.out.printf("Mismatch at word %d: ours=0x%016X bc=0x%016X%n", i, myWords[i], bcWords[i]);
                }
            }

            if (ok)
            {
                System.out.println("MATCH: our SHAKE256w(empty) equals BouncyCastle for first 4 words.");
            }
        }
        catch (ClassNotFoundException cnf)
        {
            System.out.println("BouncyCastle not on classpath; skipping BC comparison.");
        }
    }
}