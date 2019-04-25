package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javacard.framework.Util;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class EPAppletTest {

    private static final byte[] TEST_APPLET1_AID_BYTES = Hex.decode("01020304050607080A");
    private static final AID appletAID = new AID(TEST_APPLET1_AID_BYTES, (short) 0, (byte) TEST_APPLET1_AID_BYTES.length);

    @Test
    public void EPtest() {

        JavaxSmartCardInterface sim = new JavaxSmartCardInterface();
        sim.installApplet(appletAID, EPApplet.class);
        sim.selectApplet(appletAID);

        byte cla = 2;
        byte p1 = 0;
        byte p2 = 0;

        // check card number
        byte[] data1 = new byte[]{0, 4};
        CommandAPDU c1 = new CommandAPDU(cla, 0, p1, p2, data1, 2);
        ResponseAPDU r1 = sim.transmitCommand(c1);

        short cardNumber = Util.getShort(r1.getData(), (short) 1);
        assertEquals((short) 4, cardNumber);

        // check soft limit
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 1900);
        CommandAPDU c2 = new CommandAPDU(cla, 1, p1, p2, data2, 2);
        ResponseAPDU r2 = sim.transmitCommand(c2);

        System.out.println(r2 + " " + Arrays.toString(r2.getData()));

        byte statusCode2 = r2.getData()[1];
        assertEquals(1, statusCode2);

        // check pin
        byte[] data3 = new byte[]{0, 0};
        Util.setShort(data3, (short) 0, (short) 0);
        CommandAPDU c3 = new CommandAPDU(cla, 2, p1, p2, data3, 2);
        ResponseAPDU r3 = sim.transmitCommand(c3);

        System.out.println(r3 + " " + Arrays.toString(r3.getData()));

        byte statusCode3 = r3.getData()[1];
        assertEquals(1, statusCode3);

    }

}
