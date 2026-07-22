package Chameleon;

import javax.smartcardio.*;

import java.security.SecureRandom;
import java.util.List;

public class RealCardTestBase {

    private static final byte CLA = (byte)0x00;

    private static int apduCount = 0;
    private static int bytesSent = 0;
    private static int bytesReceived = 0;

    public static void main(String[] args) throws Exception {

        // Find readers
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();

        if (terminals.isEmpty()) {
            throw new RuntimeException("No smart card readers found");
        }

        System.out.println("Available readers:");

        for (int i = 0; i < terminals.size(); i++) {
            System.out.println(
                i + ": " + terminals.get(i).getName());
        }

        CardTerminal terminal = terminals.get(0);

        System.out.println("\nUsing: " + terminal.getName());

        terminal.waitForCardPresent(0);

        Card card = terminal.connect("*");

        System.out.println("Connected");

        CardChannel channel =
                card.getBasicChannel();

        //
        // SELECT APPLET
        //
        byte[] aid = {
                (byte)0xA0,
                0x01,
                0x01,
                0x01,
                0x01,
                0x01,
                0x01
        };

        ResponseAPDU selectResp =
                send(
                    channel,
                    new CommandAPDU(
                        0x00,
                        0xA4,
                        0x04,
                        0x00,
                        aid));

        if (selectResp.getSW() != 0x9000) {
            throw new RuntimeException(
                    String.format(
                            "SELECT failed: %04X",
                            selectResp.getSW()));
        }

        System.out.println("Applet selected");

        //
        // INIT
        //
        ResponseAPDU initResp =
                send(
                    channel,
                    new CommandAPDU(
                        CLA,
                        0x10,
                        0x00,
                        0x00));

        System.out.printf(
                "INIT SW = %04X%n",
                initResp.getSW());

        //
        // INTERNAL AUTHENTICATE
        //
        SecureRandom rnd = new SecureRandom();
        byte[] challenge = new byte[4];
        rnd.nextBytes(challenge);

        send(
            channel,
            new CommandAPDU(
                CLA,
                0x88,
                0x00,
                0x00,
                challenge));

        //
        // SIGN
        //
        long start =
                System.nanoTime();

        send(
            channel,
            new CommandAPDU(
                CLA,
                0x40,
                0x00,
                0x00));

        long end =
                System.nanoTime();

        System.out.println(
                "Sign time (ns): " +
                (end - start));

        //
        // GET SIGNATURE
        //
        ResponseAPDU sigResp =
                send(
                    channel,
                    new CommandAPDU(
                        CLA,
                        0x50,
                        0x00,
                        0x00));

        byte[] signature =
                sigResp.getData();

        System.out.println(
                "Signature length = "
                + signature.length);

        System.out.println(
                "Signature = "
                + toHex(signature));

        card.disconnect(false);
    }

    private static ResponseAPDU send(
            CardChannel channel,
            CommandAPDU cmd)
            throws Exception {

        apduCount++;

        bytesSent += cmd.getBytes().length;

        ResponseAPDU resp =
                channel.transmit(cmd);

        bytesReceived += resp.getBytes().length;

        System.out.println(
                ">> " +
                toHex(cmd.getBytes()));

        System.out.println(
                "<< " +
                toHex(resp.getBytes()));

        System.out.printf(
                "SW=%04X%n",
                resp.getSW());

        System.out.println();

        return resp;
    }

    private static String toHex(byte[] data) {

        StringBuilder sb =
                new StringBuilder();

        for (byte b : data) {
            sb.append(
                    String.format(
                            "%02X ",
                            b));
        }

        return sb.toString();
    }
}
