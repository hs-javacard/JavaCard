package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static javacard.framework.ISO7816.SW_CONDITIONS_NOT_SATISFIED;
import static org.junit.Assert.assertEquals;

public class DepositTest {

    private static final byte CLA = 3;

    @Test
    public void testSuccess() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        // check card number
        byte[] data1 = new byte[]{0, 4};
        ResponseAPDU r1 = TestHelper.createAndSendCommand(sim, CLA, (byte) 0, p1, p2, data1);

        short cardNumber = Util.getShort(r1.getData(), (short) 1);
        assertEquals("Incorrect r1 cla", CLA, r1.getData()[0]);
        assertEquals("Incorrect r1 card number", 4, cardNumber);
        assertEquals("Incorrect r1 data size", 3, r1.getData().length);
        assertEquals("Incorrect r1 SW", 36864, r1.getSW());

        // check card number
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 1000);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, CLA, (byte) 1, p1, p2, data2);

        short balance = Util.getShort(r2.getData(), (short) 1);
        assertEquals("Incorrect r2 cla", CLA, r2.getData()[0]);
        assertEquals("Incorrect r2 balance", 5000, balance);
        assertEquals("Incorrect r2 data size", 3, r2.getData().length);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());
    }

}
