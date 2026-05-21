package Reader;

import Reader.*;
import java.util.Scanner;

public class MainDebug {

    public static void main(String[] args) {

        ReaderManager rm = new ReaderManager();
        rm.connectAndWait();

        CardSession session = rm.getSession();

        Scanner sc = new Scanner(System.in);

        while (true) {

            System.out.print("APDU> ");
            String line = sc.nextLine();

            if (line.equalsIgnoreCase("exit"))
                break;

            try {
                byte[] apdu = hexToBytes(line);

                byte[] resp = session.transmit(apdu);

                System.out.println("<< " + toHex(resp));

            } catch (Exception e) {
                System.out.println("ERROR: " + e.getMessage());
            }
        }

        rm.close();
    }

    private static byte[] hexToBytes(String s) {
        s = s.replaceAll(" ", "");
        int len = s.length();

        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }

        return data;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();

        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }

        return sb.toString();
    }
}