package Reader;

// DLL mapping
public interface Ylt32 extends Library {

    Ylt32 INSTANCE = Native.load("ylt_32", Ylt32.class);

    Pointer OpenDevice(String port, int portNo, int baud);

    int CloseDevice(Pointer icdev);

    int CpuCardPowerOn(Pointer icdev, byte cardno,
                       byte[] rlen, byte[] resetdata);

    int CpuCardAPDU(Pointer icdev, byte cardno,
                    int slen, byte[] send,
                    IntByReference rlen,
                    byte[] recv);

    int CpuCardPowerdown(Pointer icdev, byte cardno);
}