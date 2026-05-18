package Reader;

public class ResponseApdu {

    public byte[] data;
    public int sw1;
    public int sw2;

    public boolean isOK() {
        return sw1 == 0x90 && sw2 == 0x00;
    }
}