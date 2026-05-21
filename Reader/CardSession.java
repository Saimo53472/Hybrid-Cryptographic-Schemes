package Reader;

import java.util.Arrays;

// apdu transport
public class CardSession {
    private final Pointer icdev;
    private final byte CARD_NO = 0x00;

    public CardSession(Pointer icdev) {
        this.icdev = icdev;
    }

    public void waitForCard() {
        IntByReference state = new IntByReference();

        while (true) {
            Ylt32.INSTANCE.GetIcCardState(icdev, (short)500, 0, state);

            if (state.getValue() == 1)
                break;

            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
        }
    }

    public byte[] powerOn() {

        ByteByReference len = new ByteByReference();
        byte[] atr = new byte[64];

        int r = Ylt32.INSTANCE.CpuCardPowerOn(
            icdev,
            CARD_NO,
            len,
            atr
        );

        if (r != 0)
            throw new RuntimeException("PowerOn failed");

        return Arrays.copyOf(atr, len.getValue() & 0xFF);
    }

    public ResponseApdu transmit(CommandApdu cmd) {
        byte[] resp = transmit(cmd.toBytes());
        return new ResponseApdu(resp);
    }
}
