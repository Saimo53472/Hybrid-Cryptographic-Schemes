package Reader;

import com.sun.jna.*;
import com.sun.jna.ptr.*;

public interface Ylt32 extends StdCallLibrary {

    Ylt32 INSTANCE = Native.load("ylt_32", Ylt32.class);

    Pointer OpenDevice(String port, int portNo, int baud);

    int CloseDevice(Pointer icdev);

    int CpuCardPowerOn(Pointer icdev, byte cardno, ByteByReference rlen, byte[] resetdata);

    int CpuCardAPDU(Pointer icdev, byte cardno, int slen, byte[] send, IntByReference rlen, byte[] recv);

    int CpuCardPowerdown(Pointer icdev, byte cardno);

    int GetIcCardState(Pointer icdev, short delaytime, int slot, IntByReference state);
}