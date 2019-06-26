package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static javacard.framework.ISO7816.SW_CLA_NOT_SUPPORTED;
import static javacard.framework.ISO7816.SW_CONDITIONS_NOT_SATISFIED;
import static org.junit.Assert.assertEquals;

public class ClaInsTest {

    @Test
    public void testFailIncorrectCLA1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runInit(sim);

        byte[] buffer = new byte[255];
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, (byte) 0xd5, (byte) 0, p1, p2, buffer);

        assertEquals("Incorrect r SW", SW_CLA_NOT_SUPPORTED, TestHelper.hexToDecimal(r.getSW()));
    }

    @Test
    public void testFailIncorrectCLA2() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runInit(sim);

        byte[] buffer = new byte[255];
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, (byte) 0xd0, (byte) 0, p1, p2, buffer);

        assertEquals("Incorrect r SW", SW_CLA_NOT_SUPPORTED, TestHelper.hexToDecimal(r.getSW()));
    }

    @Test
    public void testFailIncorrectINS1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        TestHelper.runInit(sim);

        byte[] buffer = new byte[255];
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, (byte) 0xd4, (byte) 1, p1, p2, buffer);

        assertEquals("Incorrect r SW", SW_CONDITIONS_NOT_SATISFIED, TestHelper.hexToDecimal(r.getSW()));
    }

    @Test
    public void testFailIncorrectCLASequence() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, (byte) 0xd4, (short) 50);
        AESKey aesKey = (AESKey) objs[0];

        // use CLA 0xd4 first and 0xd3 after that
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 50); // nonce
        Util.setShort(buffer, (short) 2, (short) 5000); // deposit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        TestHelper.createAndSendCommand(sim, (byte) 0xd4, (byte) 2, p1, p2, buffer);

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, (byte) 0xd3, (byte) 3, p1, p2, buffer);

        assertEquals("Incorrect r SW", SW_CONDITIONS_NOT_SATISFIED, TestHelper.hexToDecimal(r2.getSW()));
    }

}
