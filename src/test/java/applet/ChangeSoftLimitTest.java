package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class ChangeSoftLimitTest {

    private static final byte CLA = 1;

    @Test
    public void testSuccess1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        AESKey aesKey = TestHelper.runAuth(sim, CLA);

        // change soft limit
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 31); // nonce
        Util.setShort(buffer, (short) 2, (short) 4); // soft limit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);
        short softLimit = Util.getShort(respData, (short) 4);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r nonce", 31, nonce);
        assertEquals("Incorrect r status code", 1, respData[3]);
        assertEquals("Incorrect r returned soft limit", 4, softLimit);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testSuccess2() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        AESKey aesKey = TestHelper.runAuth(sim, CLA);

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 32); // nonce
        Util.setShort(buffer, (short) 2, (short) 5); // soft limit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);
        short softLimit = Util.getShort(respData, (short) 4);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r nonce", 32, nonce);
        assertEquals("Incorrect r status code", 1, respData[3]);
        assertEquals("Incorrect r returned soft limit", 5, softLimit);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testError() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        AESKey aesKey = TestHelper.runAuth(sim, CLA);

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 33); // nonce
        Util.setShort(buffer, (short) 2, (short) 31); // soft limit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r nonce", 33, nonce);
        assertEquals("Incorrect r status code", -1, respData[3]);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

}
