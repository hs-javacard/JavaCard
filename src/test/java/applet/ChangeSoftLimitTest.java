package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RSAPublicKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class ChangeSoftLimitTest {

    private static final byte CLA = (byte) 0xd2;

    @Test
    public void testSuccess1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuth(sim, CLA);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        // change soft limit
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 31); // nonce
        Util.setShort(buffer, (short) 2, (short) 4); // soft limit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        short nonce = Util.getShort(respData2, (short) 1);
        short softLimit = Util.getShort(respData2, (short) 4);
        short log = Util.getShort(respData2, (short) 6);

        assertEquals("Incorrect r cla", CLA, respData2[0]);
        assertEquals("Incorrect r nonce", 31, nonce);
        assertEquals("Incorrect r status code", 1, respData2[3]);
        assertEquals("Incorrect r returned soft limit", 4, softLimit);
        assertEquals("Incorrect r returned log", Log.SOFT_LIMIT_CHANGED, log);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testSuccess2() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuth(sim, CLA);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 32); // nonce
        Util.setShort(buffer, (short) 2, (short) 5); // soft limit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        short nonce = Util.getShort(respData2, (short) 1);
        short softLimit = Util.getShort(respData2, (short) 4);
        short log = Util.getShort(respData2, (short) 6);

        assertEquals("Incorrect r cla", CLA, respData2[0]);
        assertEquals("Incorrect r nonce", 32, nonce);
        assertEquals("Incorrect r status code", 1, respData2[3]);
        assertEquals("Incorrect r returned soft limit", 5, softLimit);
        assertEquals("Incorrect r returned log", Log.SOFT_LIMIT_CHANGED, log);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testError() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuth(sim, CLA);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 33); // nonce
        Util.setShort(buffer, (short) 2, (short) 31); // soft limit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        short nonce = Util.getShort(respData2, (short) 1);
        short softLimit = Util.getShort(respData2, (short) 4);
        short log = Util.getShort(respData2, (short) 6);

        assertEquals("Incorrect r cla", CLA, respData2[0]);
        assertEquals("Incorrect r nonce", 33, nonce);
        assertEquals("Incorrect r status code", -1, respData2[3]);
        assertEquals("Incorrect r returned soft limit", 5, softLimit);
        assertEquals("Incorrect r returned log", Log.SOFT_LIMIT_CHANGED, log);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

}
