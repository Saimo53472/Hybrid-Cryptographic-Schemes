package Reader;

public class CommandApdu {

    public byte cla;
    public byte ins;
    public byte p1;
    public byte p2;
    public byte[] data;

    public byte[] toBytes() {
        byte[] apdu = new byte[5 + (data != null ? data.length : 0)];

        apdu[0] = cla;
        apdu[1] = ins;
        apdu[2] = p1;
        apdu[3] = p2;
        apdu[4] = (byte)(data != null ? data.length : 0);

        if (data != null)
            System.arraycopy(data, 0, apdu, 5, data.length);

        return apdu;
    }
}
