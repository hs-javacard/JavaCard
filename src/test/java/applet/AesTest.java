package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class AesTest {

    @Test
    public void EPtest() {

        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte cla = 2;
        byte p1 = 0;
        byte p2 = 0;

        byte[] theKey = {0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d};
        RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] plaintext = new byte[32];
        AESKey sharedKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        byte[] data8 = new byte[]{0, 0};
        CommandAPDU c8 = new CommandAPDU(101, 0, p1, p2, data8, 2);
        ResponseAPDU r8 = sim.transmitCommand(c8);
        byte statusC8 = r8.getData()[1];
        byte[] responsedata = r8.getData();

        sharedKey.setKey(theKey, (short) 0);

        short len = Util.getShort(responsedata, (short) 0);
//        short blocks = (short) (len / 16);
//        if ((len % 16) > 0) {
//            blocks++;
//        }
//        short encSize = (short) (blocks * 16);

        Util.arrayCopy(responsedata, (short) (len + 2), ivdata, (short) 0, (short) 16);

        aesCipher.init(sharedKey, Cipher.MODE_DECRYPT, ivdata, (short) 0, (short) 16);

        aesCipher.doFinal(responsedata, (short) 2, (short) len, plaintext, (short) 0);
        System.out.println(new String(plaintext));
        short msglen = Util.getShort(plaintext,(short) 0);
        System.out.println("msglen is " + msglen);
//        byte statusC = r7.getData()[1];

//        if (!isRSAKeyInitialized) {
//            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//        }

    }

    private short getBlockSize(short msgSize) {
        short blocks = (short) (msgSize / 16);
        if ((msgSize % 16) > 0)
            blocks++;

        return blocks;
    }

    @Test
    public void AESDecryptOnCard() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte cla = 102;
        byte p1 = 0;
        byte p2 = 0;

        byte[] theKey = {0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d};
        RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        //byte[] plaintext = new byte[32];
        AESKey sharedKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        random.generateData(ivdata, (short) 0, (short) 16);
        sharedKey.setKey(theKey, (short) 0);


        byte[] myPlaintext = "Het geheime bericht is HENK!".getBytes();
        short msgLen = (short) myPlaintext.length;
        short toEncL = (short) (getBlockSize((short) (msgLen + 2))*16);
        byte[] toBeEncrypted = new byte[toEncL];

        Util.setShort(toBeEncrypted, (short) 0, msgLen);
        Util.arrayCopy(myPlaintext,(short) 0, toBeEncrypted, (short) 2, msgLen);

        byte[] encTarget =  new byte[toEncL+2+16];


        //Util.arrayCopy(responsedata, (short) (len + 2), ivdata, (short) 0, (short) 16);

        aesCipher.init(sharedKey, Cipher.MODE_ENCRYPT, ivdata, (short) 0, (short) 16);
        aesCipher.doFinal(toBeEncrypted, (short) 0, toEncL, encTarget, (short) 2);
        Util.setShort(encTarget, (short) 0, toEncL);
        Util.arrayCopy(ivdata, (short) 0, encTarget, (short) (toEncL + 2), (short) ivdata.length);


//        byte[] data8 = new byte[myPlaintext.length + 2];
//        byte[] data8 = new byte[]{0, 0};
        CommandAPDU c8 = new CommandAPDU(cla, 0, p1, p2, encTarget, 2);
        ResponseAPDU r8 = sim.transmitCommand(c8);
        byte[] responsedata = r8.getData();


        short recLen = Util.getShort(responsedata,(short) 0);
        byte[] recmsg = new byte[recLen];
        Util.arrayCopy(responsedata,(short) 2, recmsg, (short) 0,recLen);

        assertEquals("Sent and received msg length", recLen, msgLen);
        //assertEquals("Incorrect r1 SW", myPlaintext, recmsg);
        assertArrayEquals(myPlaintext, recmsg);

    }

}
