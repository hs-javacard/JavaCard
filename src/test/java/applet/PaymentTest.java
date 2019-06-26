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
        assertEquals("Incorrect r3 balance", 30, balance); // default amount is 40
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
        short balance = Util.getShort(respData2, (short) 3);
        short log = Util.getShort(respData2, (short) 5);

        assertEquals("Incorrect r2 cla", CLA, respData2[0]);
        assertEquals("Incorrect r2 nonce", 70, nonce);
        assertEquals("Incorrect r2 balance", 36, balance);
        assertEquals("Incorrect r2 returned log", Log.PAYMENT_COMPLETED, log);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());
    }

    @Test
    public void testFailAmountTooHigh() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, CLA, (short) 70);
        AESKey aesKey = (AESKey) objs[0];

        // 45 is more than the balance of 40
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 70); // nonce
        Util.setShort(buffer, (short) 2, (short) 45); // payment
        Util.setShort(buffer, (short) 4, (short) 13); // day number
        Util.setShort(buffer, (short) 6, (short) 2019); // year number

        TestHelper.encryptAes(aesKey, buffer, (short) 8);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r nonce", 70, nonce);
        assertEquals("Incorrect r status code", -1, respData[3]);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

    @Test
    public void testFailHardLimitReached() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, CLA, (short) 60);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        // first payment of 25
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce
        Util.setShort(buffer, (short) 2, (short) 25); // payment
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
        assertEquals("Incorrect r3 balance", 15, balance); // default amount is 40
        assertEquals("Incorrect r3 returned log", Log.PAYMENT_COMPLETED, log);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());

        // second payment of 3
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce
        Util.setShort(buffer, (short) 2, (short) 3); // payment
        Util.setShort(buffer, (short) 4, (short) 13); // day number
        Util.setShort(buffer, (short) 6, (short) 2019); // year number

        TestHelper.encryptAes(aesKey, buffer, (short) 8);
        ResponseAPDU r4 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r4.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r4 cla", CLA, respData[0]);
        assertEquals("Incorrect r4 status code", 1, respData[3]);
        assertEquals("Incorrect r4 nonce", 60, nonce);
        assertEquals("Incorrect r4 SW", 36864, r4.getSW());

        // withdraw
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce

        TestHelper.encryptAes(aesKey, buffer, (short) 2);
        ResponseAPDU r5 = TestHelper.createAndSendCommand(sim, CLA, (byte) 4, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r5.getData());
        respData2 = TestHelper.decryptRsa(pkCard, respData);

        nonce = Util.getShort(respData2, (short) 1);
        balance = Util.getShort(respData2, (short) 3);
        log = Util.getShort(respData2, (short) 5);

        assertEquals("Incorrect r5 cla", CLA, respData2[0]);
        assertEquals("Incorrect r5 nonce", 60, nonce);
        assertEquals("Incorrect r5 balance", 12, balance);
        assertEquals("Incorrect r5 returned log", Log.PAYMENT_COMPLETED, log);
        assertEquals("Incorrect r5 SW", 36864, r5.getSW());

        // third payment of 5
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce
        Util.setShort(buffer, (short) 2, (short) 5); // payment
        Util.setShort(buffer, (short) 4, (short) 13); // day number
        Util.setShort(buffer, (short) 6, (short) 2019); // year number

        TestHelper.encryptAes(aesKey, buffer, (short) 8);
        ResponseAPDU r6 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r6.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r6 cla", CLA, respData[0]);
        assertEquals("Incorrect r6 status code", -3, respData[3]);
        assertEquals("Incorrect r6 nonce", 60, nonce);
        assertEquals("Incorrect r6 SW", 36864, r6.getSW());

        // third payment of 5 again, the next day
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce
        Util.setShort(buffer, (short) 2, (short) 5); // payment
        Util.setShort(buffer, (short) 4, (short) 14); // day number
        Util.setShort(buffer, (short) 6, (short) 2019); // year number

        TestHelper.encryptAes(aesKey, buffer, (short) 8);
        ResponseAPDU r7 = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r7.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r7 cla", CLA, respData[0]);
        assertEquals("Incorrect r7 status code", 1, respData[3]);
        assertEquals("Incorrect r7 nonce", 60, nonce);
        assertEquals("Incorrect r7 SW", 36864, r7.getSW());

        // withdraw
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 60); // nonce

        TestHelper.encryptAes(aesKey, buffer, (short) 2);
        ResponseAPDU r8 = TestHelper.createAndSendCommand(sim, CLA, (byte) 4, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r8.getData());
        respData2 = TestHelper.decryptRsa(pkCard, respData);

        nonce = Util.getShort(respData2, (short) 1);
        balance = Util.getShort(respData2, (short) 3);
        log = Util.getShort(respData2, (short) 5);

        assertEquals("Incorrect r8 cla", CLA, respData2[0]);
        assertEquals("Incorrect r8 nonce", 60, nonce);
        assertEquals("Incorrect r8 balance", 7, balance);
        assertEquals("Incorrect r8 returned log", Log.PAYMENT_COMPLETED, log);
        assertEquals("Incorrect r8 SW", 36864, r8.getSW());
    }

}
