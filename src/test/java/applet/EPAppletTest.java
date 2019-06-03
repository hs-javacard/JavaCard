package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.framework.*;
import javacard.security.*;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class EPAppletTest {

    private static final byte[] TEST_APPLET1_AID_BYTES = Hex.decode("01020304050607080A");
    private static final AID appletAID = new AID(TEST_APPLET1_AID_BYTES, (short) 0, (byte) TEST_APPLET1_AID_BYTES.length);

    @Test
    public void EPtest() {

        JavaxSmartCardInterface sim = new JavaxSmartCardInterface();
        sim.installApplet(appletAID, EPApplet.class);
        sim.selectApplet(appletAID);

        byte cla = 2;
        byte p1 = 0;
        byte p2 = 0;

//        // check card number
//        byte[] data1 = new byte[]{0, 4};
//        CommandAPDU c1 = new CommandAPDU(cla, 0, p1, p2, data1, 2);
//        ResponseAPDU r1 = sim.transmitCommand(c1);
//
//        short cardNumber = Util.getShort(r1.getData(), (short) 1);
//        assertEquals((short) 4, cardNumber);
//
//        // check soft limit
//        byte[] data2 = new byte[]{0, 0};
//        Util.setShort(data2, (short) 0, (short) 1500);
//        CommandAPDU c2 = new CommandAPDU(cla, 1, p1, p2, data2, 2);
//        ResponseAPDU r2 = sim.transmitCommand(c2);
//
//        System.out.println(r2 + " " + Arrays.toString(r2.getData()));
//
//        byte statusCode2 = r2.getData()[1];
//        assertEquals(-2, statusCode2);
//
//        // check pin
//        byte[] data3 = new byte[]{0, 0};
//        short pin = 4;
//        Util.setShort(data3, (short) 0, (short) pin);
//        CommandAPDU c3 = new CommandAPDU(cla, 2, p1, p2, data3, 2);
//        ResponseAPDU r3 = sim.transmitCommand(c3); // 3x wrong pin
//        ResponseAPDU r4 = sim.transmitCommand(c3);
////        ResponseAPDU r5 = sim.transmitCommand(c3);
//
//        System.out.println(r3 + " " + Arrays.toString(r3.getData()));
//
//        byte statusCode3 = r3.getData()[1];
//        assertEquals(-1, statusCode3);
//
//
//        byte[] data4 = new byte[]{0, 0};
//        short pin2 = 5;
//        Util.setShort(data4, (short) 0, (short) pin2);
//        CommandAPDU c31 = new CommandAPDU(cla, 2, p1, p2, data4, 2);
//        ResponseAPDU r31 = sim.transmitCommand(c31);
//        byte statusCode31 = r31.getData()[1];
//        assertEquals(1, statusCode31);
//
//
//        byte[] data6 = new byte[]{0,0};
//        CommandAPDU c6 = new CommandAPDU(100, 0, p1, p2, data6, 2);
//        ResponseAPDU r6 = sim.transmitCommand(c6);
//        byte statusC = r6.getData()[1];
//
//        byte[] keyBuffer = r6.getData();
//        short expSize = Util.getShort(keyBuffer,(short) 0);
//        short modSize = Util.getShort(keyBuffer,(short) 2);
//
//        RSAPublicKey cardPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);
//
//        cardPub.setExponent(keyBuffer,(short) 4, expSize);
//        cardPub.setModulus(keyBuffer,(short) (4 + expSize), modSize);
//
////
//        final byte[] myMessage = "Henk!".getBytes();
//        short nonce = 0;
//        final byte[] msg = new byte[118];
//        Util.setShort(msg,(short) 0,nonce);
//        Util.arrayCopy(myMessage,(short)0 ,msg,(short) 2, (short) myMessage.length);
//
//        System.out.println(cardPub.isInitialized());
//        Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
////        if (myMessage.length >= modSize.length - 11) {
////            System.out.println("Data too long!");
////        }
//        rsaCipher.init(cardPub, Cipher.MODE_ENCRYPT);
//
//
//
//        final byte[] encryptedMsg = JCSystem.makeTransientByteArray(
//                (short) 128, JCSystem.CLEAR_ON_DESELECT);
////        rsaCipher.doFinal()
//        rsaCipher.doFinal(msg, (short) 0,
//                (short) msg.length, encryptedMsg, (short) 0);

//        System.out.println();

//
//        byte[] data7 = new byte[128];
//        Util.arrayCopy(encryptedMsg,(short) 0, data7,(short) 0,(short) 128);
//        CommandAPDU c7 = new CommandAPDU(100, 1, p1, p2, data7, 2);
//        ResponseAPDU r7 = sim.transmitCommand(c7);

        byte[] theKey = {0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d};
        RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] plaintext = new byte[32];
        AESKey sharedKey = (AESKey) KeyBuilder.buildKey (KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        byte[] data8 = new byte[]{0,0};
        CommandAPDU c8 = new CommandAPDU(101, 0, p1, p2, data8, 2);
        ResponseAPDU r8 = sim.transmitCommand(c8);
        byte statusC8 = r8.getData()[1];
        byte[] responsedata = r8.getData();

        sharedKey.setKey(theKey, (short) 0);

        short len = Util.getShort(responsedata, (short) 0);
        short blocks = (short) (len/16);
        if ((len % 16) > 0 ) {
            blocks++;
        }
        short encSize = (short) (blocks*16);




        Util.arrayCopy(responsedata, (short) (encSize + 2), ivdata,(short) 0, (short) 16);



        aesCipher.init(sharedKey, Cipher.MODE_DECRYPT, ivdata, (short) 0 , (short) 16);

        aesCipher.doFinal(responsedata, (short) 2, (short) encSize, plaintext, (short) 0);
        System.out.println( new String(plaintext));
//        byte statusC = r7.getData()[1];

//        if (!isRSAKeyInitialized) {
//            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//        }


    }

}
