package Reader;

import java.util.Arrays;

public class CardSession {
    private final Pointer icdev;
    private final byte CARD_NO = 0x00;

    public CardSession(Pointer icdev) {
        this.icdev = icdev;
    }

    public void waitForCard() {
        IntByReference state = new IntByReference();

        while (true) {
            Ylt32.INSTANCE.GetIcCardState(
                icdev, (short) 500, 0, state
            );

            if (state.getValue() == 1)
                break;
        }
    }

    public byte[] powerOn() {

        byte[] len = new byte[1];
        byte[] atr = new byte[64];

        int r = Ylt32.INSTANCE.CpuCardPowerOn(
            icdev,
            CARD_NO,
            len,
            atr
        );

        if (r != 0)
            throw new RuntimeException("PowerOn failed");

        return Arrays.copyOf(atr, len[0]);
    }

    public byte[] transmit(byte[] apdu) {

        IntByReference rlen = new IntByReference();
        byte[] resp = new byte[256];

        int r = Ylt32.INSTANCE.CpuCardAPDU(
            icdev,
            CARD_NO,
            apdu.length,
            apdu,
            rlen,
            resp
        );

        if (r != 0)
            throw new RuntimeException("APDU failed");

        return Arrays.copyOf(resp, rlen.getValue());
    }
}
