package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static javacard.framework.ISO7816.SW_CONDITIONS_NOT_SATISFIED;
import static org.junit.Assert.assertEquals;

public class PaymentTest {

    private static final byte CLA = 2;

    @Test
    public void testSuccessWithPin() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

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

        // check soft limit
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 2500);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, CLA, (byte) 1, p1, p2, data2);

        assertEquals("Incorrect r2 cla", CLA, r2.getData()[0]);
        assertEquals("Incorrect r2 status code", -2, r2.getData()[1]);
        assertEquals("Incorrect r2 data size", 2, r2.getData().length);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());

        // check pin
        byte[] data3 = new byte[]{0, 0};
        Util.setShort(data3, (short) 0, (short) 0);
        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data3);

        assertEquals("Incorrect r3 cla", CLA, r3.getData()[0]);
        assertEquals("Incorrect r3 status code", 1, r3.getData()[1]);
        assertEquals("Incorrect r3 data size", 2, r3.getData().length);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());

        // withdraw
        byte[] data4 = new byte[]{};
        ResponseAPDU r4 = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, data4);

        short balance = Util.getShort(r4.getData(), (short) 1);
        assertEquals("Incorrect r4 cla", CLA, r4.getData()[0]);
        assertEquals("Incorrect r4 balance", 1500, balance);
        assertEquals("Incorrect r4 data size", 3, r4.getData().length);
        assertEquals("Incorrect r4 SW", 36864, r4.getSW());
    }

    @Test
    public void testSuccessWithoutPin() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

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

        // check soft limit: no pin needed because 1500 < softLimit of 2000
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 1500);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, CLA, (byte) 1, p1, p2, data2);

        assertEquals("Incorrect r2 cla", CLA, r2.getData()[0]);
        assertEquals("Incorrect r2 status code", 1, r2.getData()[1]);
        assertEquals("Incorrect r2 data size", 2, r2.getData().length);
        assertEquals("Incorrect r2 SW", 36864, r1.getSW());

        // withdraw
        byte[] data4 = new byte[]{};
        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, data4);

        short balance = Util.getShort(r3.getData(), (short) 1);
        assertEquals("Incorrect r3 cla", CLA, r3.getData()[0]);
        assertEquals("Incorrect r3 balance", 2500, balance);
        assertEquals("Incorrect r3 data size", 3, r3.getData().length);
        assertEquals("Incorrect r3 SW", 36864, r1.getSW());
    }

    @Test
    public void testPinTries() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

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

        // check soft limit
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 2500);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, CLA, (byte) 1, p1, p2, data2);

        assertEquals("Incorrect r2 cla", CLA, r2.getData()[0]);
        assertEquals("Incorrect r2 status code", -2, r2.getData()[1]);
        assertEquals("Incorrect r2 data size", 2, r2.getData().length);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());

        // check incorrect pin
        byte[] data3 = new byte[]{0, 0};
        Util.setShort(data3, (short) 0, (short) 4);

        // First incorrect pin
        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data3);

        assertEquals("Incorrect r3 cla", CLA, r3.getData()[0]);
        assertEquals("Incorrect r3 status code", -1, r3.getData()[1]);
        assertEquals("Incorrect r3 data size", 2, r3.getData().length);

        // Second incorrect pin
        r3 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data3);

        assertEquals("Incorrect r3 cla", CLA, r3.getData()[0]);
        assertEquals("Incorrect r3 status code", -1, r3.getData()[1]);
        assertEquals("Incorrect r3 data size", 2, r3.getData().length);

        // Third incorrect pin
        r3 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data3);

        assertEquals("Incorrect r3 cla", CLA, r3.getData()[0]);
        assertEquals("Incorrect r3 status code", -1, r3.getData()[1]);
        assertEquals("Incorrect r3 data size", 2, r3.getData().length);

        byte[] data4 = new byte[]{0, 0};
        Util.setShort(data4, (short) 0, (short) 0);

        // Even correct pin should fail
        ResponseAPDU r4 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data4);

        assertEquals("Incorrect r4 cla", CLA, r4.getData()[0]);
        assertEquals("Incorrect r4 status code", -1, r4.getData()[1]);
        assertEquals("Incorrect r4 data size", 2, r4.getData().length);

        // withdraw should also fail
        byte[] data5 = new byte[]{};
        ResponseAPDU r5 = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, data5);

        assertEquals("Incorrect r5 data size", 0, r5.getData().length);
        assertEquals("Incorrect r5 SW", SW_CONDITIONS_NOT_SATISFIED, r5.getSW());
    }

}
