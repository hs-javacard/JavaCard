package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class ChangeSoftLimitTest {

    private static final byte CLA = 1;

    @Test
    public void testSuccess1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runAuth(sim, CLA);

        // change soft limit
        byte[] data = new byte[]{0, 4};
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data);

        short softLimit = Util.getShort(r.getData(), (short) 2);
        assertEquals("Incorrect r cla", CLA, r.getData()[0]);
        assertEquals("Incorrect r status code", 1, r.getData()[1]);
        assertEquals("Incorrect r returned soft limit", 4, softLimit);
        assertEquals("Incorrect r data size", 4, r.getData().length);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testSuccess2() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runAuth(sim, CLA);

        byte[] data = new byte[2];
        Util.setShort(data, (short) 0, (short) 10000);

        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data);

        short softLimit = Util.getShort(r.getData(), (short) 2);
        assertEquals("Incorrect r cla", CLA, r.getData()[0]);
        assertEquals("Incorrect r status code", 1, r.getData()[1]);
        assertEquals("Incorrect r returned soft limit", 10000, softLimit);
        assertEquals("Incorrect r data size", 4, r.getData().length);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testError() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runAuth(sim, CLA);

        byte[] data = new byte[2];
        Util.setShort(data, (short) 0, (short) 10001);

        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data);

        assertEquals("Incorrect r cla", CLA, r.getData()[0]);
        assertEquals("Incorrect r status code", -1, r.getData()[1]);
        assertEquals("Incorrect r data size", 4, r.getData().length);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }


}
