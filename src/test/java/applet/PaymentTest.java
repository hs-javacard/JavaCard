package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RSAPublicKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class PaymentTest {

    private static final byte CLA = (byte) 0xd3;

    @Test
    public void testSuccessWithPin() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, CLA, (short) 60);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        // check soft limit
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce
        Util.setShort(buffer, (short) 2, (short) 10); // payment
        Util.setShort(buffer, (short) 4, (short) 13); // day number
        Util.setShort(buffer, (short) 6, (short) 2019); // year number

        TestHelper.encryptAes(aesKey, buffer, (short) 8);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r status code", -2, respData[3]);
        assertEquals("Incorrect r nonce", 60, nonce);
        assertEquals("Incorrect r SW", 36864, r.getSW());

        // check pin
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce
        Util.setShort(buffer, (short) 2, (short) 3); // pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r2.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r2 cla", CLA, respData[0]);
        assertEquals("Incorrect r2 nonce", 60, nonce);
        assertEquals("Incorrect r2 status code", 1, respData[3]);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());

        // withdraw
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce

        TestHelper.encryptAes(aesKey, buffer, (short) 2);
        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, CLA, (byte) 4, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r3.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        nonce = Util.getShort(respData2, (short) 1);
        short balance = Util.getShort(respData2, (short) 3);
        short log = Util.getShort(respData2, (short) 5);

        assertEquals("Incorrect r3 cla", CLA, respData2[0]);
        assertEquals("Incorrect r3 nonce", 60, nonce);
        assertEquals("Incorrect r3 balance", 10, balance); // default amount is 20
        assertEquals("Incorrect r3 returned log", Log.PAYMENT_COMPLETED, log);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());
    }

    @Test
    public void testSuccessWithoutPin() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, CLA, (short) 70);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        // check soft limit: no pin needed because 4 < softLimit of 10
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 70); // nonce
        Util.setShort(buffer, (short) 2, (short) 4); // payment
        Util.setShort(buffer, (short) 4, (short) 13); // day number
        Util.setShort(buffer, (short) 6, (short) 2019); // year number

        TestHelper.encryptAes(aesKey, buffer, (short) 8);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r nonce", 70, nonce);
        assertEquals("Incorrect r status code", 1, respData[3]);
        assertEquals("Incorrect r SW", 36864, r.getSW());

        // withdraw
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 70); // nonce

        TestHelper.encryptAes(aesKey, buffer, (short) 2);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, CLA, (byte) 4, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r2.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        nonce = Util.getShort(respData2, (short) 1);
        short log = Util.getShort(respData2, (short) 3);

        assertEquals("Incorrect r2 cla", CLA, respData2[0]);
        assertEquals("Incorrect r nonce", 70, nonce);
        assertEquals("Incorrect r returned log", Log.PAYMENT_COMPLETED, log);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());
    }

}
