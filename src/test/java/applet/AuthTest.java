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

        byte cla = (byte) 0xd2;
        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runInit(sim);
        RSAPublicKey cardPk = (RSAPublicKey) objs[0];
        byte[] secret = (byte[]) objs[1];

        KeyPair keyPair = TestHelper.createKeyPairRsa();

        byte[] aesKeyBuffer = TestHelper.keyBufferAes();
        AESKey aesKey = TestHelper.createKeyAes();

        /////////////////////////////////////////////////////

        byte[] buffer = new byte[255];
        ResponseAPDU r1 = TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, buffer);

        byte[] encData = new byte[128];
        Util.arrayCopy(r1.getData(), (short) 0, encData, (short) 0, (short) 128);
        byte[] respData = TestHelper.decryptRsa(cardPk, encData);

        short cardNumberDecr = Util.getShort(respData, (short) 1);
        short cardNumberPlain = Util.getShort(r1.getData(), (short) 128);

        assertEquals("Incorrect r1 cla", cla, respData[0]);
        assertEquals("Incorrect r1 card number", 1, cardNumberDecr);
        assertEquals("Incorrect r1 card number", 1, cardNumberPlain);
        assertEquals("Incorrect r1 SW", 36864, r1.getSW());

        // set AES key
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 12);                                   //nonce
        Util.arrayCopy(aesKeyBuffer, (short) 0, buffer, (short) 2, (short) 16);         //aesKey
        Util.arrayCopy(secret, (short) 0, buffer, (short) 18, (short) 16);              //secret
        TestHelper.writePkRsa((RSAPublicKey) keyPair.getPublic(), buffer, (short) 34);  //public key terminal

        TestHelper.encryptRsa(cardPk, buffer, (short) 34);
        ResponseAPDU r2 = TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r2.getData());
        short nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r2 cla", cla, respData[0]);
        assertEquals("Incorrect r2 nonce", 12, nonce);
        assertEquals("Incorrect r2 status code", 1, respData[3]);
        assertEquals("Incorrect r2 SW", 36864, r2.getSW());

        // First incorrect pin
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 13); //nonce
        Util.setShort(buffer, (short) 2, (short) 4); //pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r3.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r3 cla", cla, respData[0]);
        assertEquals("Incorrect r3 nonce", 13, nonce);
        assertEquals("Incorrect r3 status code", -1, respData[3]);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());

        // Second incorrect pin
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 14); //nonce
        Util.setShort(buffer, (short) 2, (short) 4); //pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r3.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r3 cla", cla, respData[0]);
        assertEquals("Incorrect r3 nonce", 14, nonce);
        assertEquals("Incorrect r3 status code", -1, respData[3]);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());

        // Third incorrect pin
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 15); //nonce
        Util.setShort(buffer, (short) 2, (short) 4); //pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r3.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r3 cla", cla, respData[0]);
        assertEquals("Incorrect r3 nonce", 15, nonce);
        assertEquals("Incorrect r3 status code", -1, respData[3]);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());

        // Even correct pin should fail
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 16); //nonce
        Util.setShort(buffer, (short) 2, (short) 3); //pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        r3 = TestHelper.createAndSendCommand(sim, cla, (byte) 2, p1, p2, buffer);

        respData = TestHelper.decryptAes(aesKey, r3.getData());
        nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r3 cla", cla, respData[0]);
        assertEquals("Incorrect r3 nonce", 16, nonce);
        assertEquals("Incorrect r3 status code", -1, respData[3]);
        assertEquals("Incorrect r3 SW", 36864, r3.getSW());
    }

}
