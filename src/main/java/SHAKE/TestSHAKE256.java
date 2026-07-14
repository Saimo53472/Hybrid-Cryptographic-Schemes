package SHAKE;

/**
 * Test harness for the Java Card–friendly SHAKE256JC + KeccakF1600 implementation.
 *
 * - Produces 32 bytes (4 words) from SHAKE256("") using SHAKE256JC (no internal allocations).
 * - Compares the byte output against BouncyCastle's SHAKEDigest when bcprov is on the classpath.
 *
 * Compile:
 *   javac -d out -cp "path/to/bcprov-jdk18on-1.84.jar" src/main/java/SHAKE/*.java
 *
 * Run:
 *   java -cp "out;path/to/bcprov-jdk18on-1.84.jar" SHAKE.TestSHAKE256
 *
 * (On Unix/macOS replace ; with : in the classpath.)
 */
public class TestSHAKE256
{
    private static String toHex(byte[] b, int off, int len)
    {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++)
        {
            int v = b[off + i] & 0xFF;
            if (v < 16) sb.append('0');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    private static byte[] buildExpectedMessage() {
        byte[] msg = new byte[255];

        int pos = 0;

        msg[pos++] = 0x05;
        msg[pos++] = 0x01;
        msg[pos++] = 0x08;

        byte[] dynamic = {
                (byte)0x6c,
                (byte)0x55,
                (byte)0x44,
                (byte)0x79,
                (byte)0x7a,
                (byte)0x91,
                (byte)0x11,
                (byte)0x5d
        };

        System.arraycopy(dynamic, 0, msg, pos, dynamic.length);
        pos += dynamic.length;

        while (pos < 251) {
            msg[pos++] = (byte)0xBB;
        }

        msg[pos++] = 0x01;
        msg[pos++] = 0x02;
        msg[pos++] = 0x03;
        msg[pos++] = 0x04;

        return msg;
    }

    public static void main(String[] args) throws Exception
    {
        byte[] msg = buildExpectedMessage();

        // Caller-provided buffers (on Java Card make these transient)
        byte[] state = new byte[200];
        int[] scratch = new int[120];
        byte[] tmp8 = new byte[8];
        byte[] singleByte = new byte[1];

        // Create the Java Card–friendly SHAKE instance
        SHAKE256JC shake = new SHAKE256JC(state, scratch);

        // Produce 32 bytes (4 words) from our implementation
        int outBytes = 32;
        byte[] ourOut = new byte[outBytes];
        shake.reset();
        shake.absorbXor(msg, 0, msg.length);
        shake.finalizeSqueeze();
        shake.squeezeBytes(ourOut, 0, outBytes);

        System.out.println("Our SHAKE256(empty) bytes (hex):");
        System.out.println(toHex(ourOut, 0, ourOut.length));

        // Also demonstrate SHAKE256w (hi/lo int pairs) output
        int words = 4;
        int[] hi = new int[words];
        int[] lo = new int[words];
        // Reuse the instance for words output: use the helper that resets/absorbs/etc.
        shake.shake256wIntoIntPairs(msg, 0, msg.length, words, hi, lo, tmp8);

        System.out.println("Our SHAKE256w(empty) first 4 words (hi/lo -> 64-bit LE):");
        for (int i = 0; i < words; i++)
        {
            long val = (((long)hi[i]) << 32) | ((long)lo[i] & 0xFFFFFFFFL);
            System.out.printf("word[%d] = 0x%016X%n", i, val);
        }

        // Compare to BouncyCastle (if available) using reflection so compilation doesn't require BC.
        try
        {
            Class<?> cl = Class.forName("org.bouncycastle.crypto.digests.SHAKEDigest");
            Object bc = cl.getConstructor(int.class).newInstance(256);
            java.lang.reflect.Method doOutput = cl.getMethod("doOutput", byte[].class, int.class, int.class);

            byte[] bcOut = new byte[outBytes];
            doOutput.invoke(bc, bcOut, 0, bcOut.length);

            System.out.println("BouncyCastle SHAKE256(empty) bytes (hex):");
            System.out.println(toHex(bcOut, 0, bcOut.length));

            boolean equal = true;
            for (int i = 0; i < outBytes; i++)
            {
                if (ourOut[i] != bcOut[i])
                {
                    equal = false;
                    break;
                }
            }
            System.out.println("Byte-level match with BouncyCastle? " + equal);

            if (!equal)
            {
                System.out.println("First differing byte indices (ours != bc):");
                for (int i = 0; i < outBytes; i++)
                {
                    if (ourOut[i] != bcOut[i])
                    {
                        System.out.printf("i=%d ours=0x%02X bc=0x%02X%n", i, ourOut[i] & 0xFF, bcOut[i] & 0xFF);
                    }
                }
            }
        }
        catch (ClassNotFoundException cnf)
        {
            System.out.println("BouncyCastle not on classpath; skipping BC comparison.");
        }
    }
}