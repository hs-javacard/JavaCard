package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class ChangePinTest {

    private static final byte CLA = 0;

    @Test
    public void testSuccess1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();
        //TestHelper.runInit(sim);

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runAuth(sim, CLA);

        byte[] data = new byte[2];
        Util.setShort(data, (short) 0, (short) 1234);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, data);

        assertEquals("Incorrect r cla", CLA, r.getData()[0]);
        assertEquals("Incorrect r status code", 1, r.getData()[1]);
        assertEquals("Incorrect r data size", 2, r.getData().length);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }
}
