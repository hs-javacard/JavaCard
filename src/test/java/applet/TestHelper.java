package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

class TestHelper {

    private static final byte[] TEST_APPLET1_AID_BYTES = Hex.decode("01020304050607080A");
    private static final AID appletAID = new AID(TEST_APPLET1_AID_BYTES, (short) 0, (byte) TEST_APPLET1_AID_BYTES.length);

    static JavaxSmartCardInterface createInterface() {
        JavaxSmartCardInterface sim = new JavaxSmartCardInterface();
        sim.installApplet(appletAID, EPApplet.class);
        sim.selectApplet(appletAID);

        return sim;
    }

    static ResponseAPDU createAndSendCommand(JavaxSmartCardInterface sim, byte cla, byte ins, byte p1, byte p2, byte[] data) {
        CommandAPDU c1 = new CommandAPDU(cla, ins, p1, p2, data, 2);
        return sim.transmitCommand(c1);
    }

    static ResponseAPDU runInit(JavaxSmartCardInterface sim) {
        byte cla = -1;
        byte p1 = 0;
        byte p2 = 0;

        byte[] data1 = new byte[14];

        Util.setShort(data1, (short) 4, (short) 1); // cardNumber
        Util.setShort(data1, (short) 6, (short) 2); // balance
        Util.setShort(data1, (short) 8, (short) 3); // pin
        Util.setShort(data1, (short) 10, (short) 4); // softLimit
        Util.setShort(data1, (short) 12, (short) 5); // hardLimit

        return TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, data1);
    }

    static void runAuth(JavaxSmartCardInterface sim, byte cla) {
        byte p1 = 0;
        byte p2 = 0;

        // check card number
        byte[] data1 = new byte[]{0, 4};
        TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, data1);

        // check pin
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 0);
        TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, data2);
    }

}
