package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class AuthTest {

    @Test
    public void runAuth() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

        byte cla = 1;
        byte p1 = 0;
        byte p2 = 0;


        // check card number
        byte[] data1 = new byte[]{0, 4};
        ResponseAPDU r1 = TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, data1);

        short cardNumber = Util.getShort(r1.getData(), (short) 1);
        assertEquals("Incorrect r1 cla", cla, r1.getData()[0]);
        assertEquals("Incorrect r1 card number", 4, cardNumber);
        assertEquals("Incorrect r1 data size", 3, r1.getData().length);
        assertEquals("Incorrect r1 SW", 36864, r1.getSW());

        // check incorrect pin
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 4);

        // First incorrect pin
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, data2);

        assertEquals("Incorrect r2 cla", cla, r2.getData()[0]);
        assertEquals("Incorrect r2 status code", -1, r2.getData()[1]);
        assertEquals("Incorrect r2 data size", 2, r2.getData().length);

        // Second incorrect pin
        r2 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, data2);

        assertEquals("Incorrect r2 cla", cla, r2.getData()[0]);
        assertEquals("Incorrect r2 status code", -1, r2.getData()[1]);
        assertEquals("Incorrect r2 data size", 2, r2.getData().length);

        // Third incorrect pin
        r2 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, data2);

        assertEquals("Incorrect r2 cla", cla, r2.getData()[0]);
        assertEquals("Incorrect r2 status code", -1, r2.getData()[1]);
        assertEquals("Incorrect r2 data size", 2, r2.getData().length);

        byte[] data3 = new byte[]{0, 0};
        Util.setShort(data3, (short) 0, (short) 0);

        // Even correct pin should fail
        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, data3);

        assertEquals("Incorrect r3 cla", cla, r3.getData()[0]);
        assertEquals("Incorrect r3 status code", -1, r3.getData()[1]);
        assertEquals("Incorrect r3 data size", 2, r3.getData().length);

    }

}
