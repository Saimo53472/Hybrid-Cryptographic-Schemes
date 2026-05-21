package Reader;

// Devices lifecycle
public class ReaderManager {

    private ReaderDevice device;
    private CardSession session;

    public void connectAndWait() {
        device = new ReaderDevice();
        device.open(); // opens connection to the usb reader 

        session = new CardSession(device.getHandle()); // communication channel to the card
        session.waitForCard(); // waits until a card is physically inserted
        session.powerOn(); // powers on the card
    }

    public CardSession getSession() {
        return session;
    }

    public void close() {
        if (session != null) session.close();
        if (device != null) device.close();
    }
}
