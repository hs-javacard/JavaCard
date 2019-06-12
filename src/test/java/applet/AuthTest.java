package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
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

        RSAPublicKey cardPk = TestHelper.runInit(sim);
        KeyPair keyPair = TestHelper.createKeyPairRsa();

        byte[] aesKeyBuffer = TestHelper.keyBufferAes();
        AESKey aesKey = TestHelper.createKeyAes();

        /////////////////////////////////////////////////////

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 11); //nonce
        TestHelper.writePkRsa((RSAPublicKey) keyPair.getPublic(), buffer, (short) 2);

        // check pkKeyTerminal number
        ResponseAPDU r1 = TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, buffer);

        byte[] respData = TestHelper.decryptRsa(keyPair.getPrivate(), r1.getData());
        short nonce = Util.getShort(respData, (short) 1);
        short cardNumber = Util.getShort(respData, (short) 3);

        assertEquals("Incorrect r1 cla", cla, respData[0]);
        assertEquals("Incorrect r1 nonce", 11, nonce);
        assertEquals("Incorrect r1 card number", 1, cardNumber);
        assertEquals("Incorrect r1 SW", 36864, r1.getSW());

        // set AES key
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 12); //nonce
        Util.arrayCopy(aesKeyBuffer, (short) 0, buffer, (short) 2, (short) 16); //aesKey

        TestHelper.encryptRsa(cardPk, buffer, (short) 18);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r2.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r2 cla", cla, respData[0]);
        assertEquals("Incorrect r2 nonce", 12, nonce);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());

//        // check incorrect pin
//        buffer = new byte[255];
//        Util.setShort(buffer, (short) 0, (short) 13); //nonce
//        Util.setShort(buffer, (short) 2, (short) 4); //pin
//
//        // First incorrect pin
//        TestHelper.encryptAes(aesKey, buffer, (short) 4);
//        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);
//
//        respData = TestHelper.decryptAes(aesKey, r3.getData());
//        nonce = Util.getShort(respData, (short) 1);
//
//        assertEquals("Incorrect r3 cla", cla, respData[0]);
//        assertEquals("Incorrect r3 nonce", 13, nonce);
//        assertEquals("Incorrect r3 status code", -1, r2.getData()[3]);
//        assertEquals("Incorrect r3 SW", 36864, r2.getSW());
//
//        // Second incorrect pin
//        TestHelper.encryptAes(aesKey, buffer, (short) 4);
//        r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);
//
//        respData = TestHelper.decryptAes(aesKey, r3.getData());
//        nonce = Util.getShort(respData, (short) 1);
//
//        assertEquals("Incorrect r3 cla", cla, respData[0]);
//        assertEquals("Incorrect r3 nonce", 14, nonce);
//        assertEquals("Incorrect r3 status code", -1, r2.getData()[3]);
//        assertEquals("Incorrect r3 SW", 36864, r2.getSW());
//
//        // Third incorrect pin
//        TestHelper.encryptAes(aesKey, buffer, (short) 4);
//        r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);
//
//        respData = TestHelper.decryptAes(aesKey, r3.getData());
//        nonce = Util.getShort(respData, (short) 1);
//
//        assertEquals("Incorrect r3 cla", cla, respData[0]);
//        assertEquals("Incorrect r3 nonce", 15, nonce);
//        assertEquals("Incorrect r3 status code", -1, r2.getData()[3]);
//        assertEquals("Incorrect r3 SW", 36864, r2.getSW());
//
//        buffer = new byte[255];
//        Util.setShort(buffer, (short) 0, (short) 16); //nonce
//        Util.setShort(buffer, (short) 2, (short) 0); //pin
//
//        byte[] data3 = new byte[]{0, 0};
//        Util.setShort(data3, (short) 0, (short) 0);
//
//        // Even correct pin should fail
//        TestHelper.encryptAes(aesKey, buffer, (short) 4);
//        r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);
//
//        respData = TestHelper.decryptAes(aesKey, r3.getData());
//        nonce = Util.getShort(respData, (short) 1);
//
//        assertEquals("Incorrect r3 cla", cla, respData[0]);
//        assertEquals("Incorrect r3 nonce", 16, nonce);
//        assertEquals("Incorrect r3 status code", -1, respData[1]);
//        assertEquals("Incorrect r3 data size", 2, respData.length);

    }

}
