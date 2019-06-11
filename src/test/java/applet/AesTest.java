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
        short blocks = (short) (len / 16);
        if ((len % 16) > 0) {
            blocks++;
        }
        short encSize = (short) (blocks * 16);

        Util.arrayCopy(responsedata, (short) (encSize + 2), ivdata, (short) 0, (short) 16);

        aesCipher.init(sharedKey, Cipher.MODE_DECRYPT, ivdata, (short) 0, (short) 16);

        aesCipher.doFinal(responsedata, (short) 2, (short) encSize, plaintext, (short) 0);
        System.out.println(new String(plaintext));
//        byte statusC = r7.getData()[1];

//        if (!isRSAKeyInitialized) {
//            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//        }

    }

}
