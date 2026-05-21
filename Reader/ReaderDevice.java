package Reader;

// Reader lifecycle
public class ReaderDevice {

    private Pointer icdev;

    public void open() {
        icdev = Ylt32.INSTANCE.OpenDevice("USB", 1, 115200); // example

        if (icdev == null)
            throw new RuntimeException("Failed to open reader");
    }

    public void close() {
        if (icdev != null)
            Ylt32.INSTANCE.CloseDevice(icdev);
    }

    public Pointer getHandle() {
        return icdev;
    }
}