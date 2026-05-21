package Reader;

import java.util.Arrays;

/**
 * Represents a response APDU returned by the smart card.
 *
 * Structure of a response APDU:
 *   DATA SW1 SW2
 *
 * - DATA: optional data returned by the card
 * - SW1/SW2: status words (always present)
 */
public class ResponseApdu {

    // full raw response (including SW1 and SW2)
    private final byte[] bytes;

    /**
     * Create a response APDU from raw bytes received from the card.
     *
     * @param bytes full APDU response (data + SW1 + SW2)
     */
    public ResponseApdu(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * @return Status Word 1
     */
    public int getSW1() {
        return bytes[bytes.length - 2] & 0xFF; // convert to unsigned
    }

    /**
     * @return Status Word 2
     */
    public int getSW2() {
        return bytes[bytes.length - 1] & 0xFF; // convert to unsigned
    }

    /**
     * @return Combined status word (SW1 << 8 | SW2)
     *         Example: 0x9000 = success
     */
    public int getSW() {
        return (getSW1() << 8) | getSW2();
    }

    /**
     * @return true if the command completed successfully (SW = 0x9000)
     */
    public boolean isOK() {
        return getSW() == 0x9000;
    }

    /**
     * @return data part of the response (without SW1/SW2)
     */
    public byte[] getData() {
        return Arrays.copyOf(bytes, bytes.length - 2);
    }

    /**
     * @return full raw APDU response
     */
    public byte[] getBytes() {
        return bytes;
    }
}