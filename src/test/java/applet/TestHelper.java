package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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
}
