package Reader;

/**
 * Represents a command APDU sent to a smart card.
 *
 * Standard structure:
 *
 * Case 1: [CLA INS P1 P2]
 * Case 2: [CLA INS P1 P2 Le]
 * Case 3: [CLA INS P1 P2 Lc DATA]
 * Case 4: [CLA INS P1 P2 Lc DATA Le]
 */
public class CommandApdu {

    // defines command class, often 0x00 or 0x80
    public byte cla;

    // defines operation
    public byte ins;

    // parameter 1 (meaning depends on instruction)
    public byte p1;

    // parameter 2 (meaning depends on instruction)
    public byte p2;

    // command data
    public byte[] data;

    // expected length of response data
    public Integer le;

    /**
     * Converts this APDU into raw bytes ready to send to the card.
     *
     * @return byte array representing the APDU command
     */
    public byte[] toBytes() {

        int lc = (data != null ? data.length : 0);

        // 4 header bytes + optional Lc + optional data + optional Le
        int size = 4 + (lc > 0 ? 1 + lc : 0) + (le != null ? 1 : 0);

        byte[] apdu = new byte[size];

        int i = 0;

        // Header
        apdu[i++] = cla;
        apdu[i++] = ins;
        apdu[i++] = p1;
        apdu[i++] = p2;

        // Data field
        if (lc > 0) {
            apdu[i++] = (byte) lc; // Lc = length of data
            System.arraycopy(data, 0, apdu, i, lc);
            i += lc;
        }

        // Expected response length
        if (le != null) {
            apdu[i] = (byte) (le & 0xFF);
        }

        return apdu;
    }

    /**
     * Helper method to create a SELECT APDU.
     *
     * @param aid Application Identifier
     * @return command APDU for SELECT
     */
    public static CommandApdu select(byte[] aid) {
        CommandApdu apdu = new CommandApdu();
        apdu.cla = (byte) 0x00;
        apdu.ins = (byte) 0xA4;
        apdu.p1 = (byte) 0x04; // select by name
        apdu.p2 = (byte) 0x00;
        apdu.data = aid;
        return apdu;
    }
}