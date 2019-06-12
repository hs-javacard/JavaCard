package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

class TestHelper {

    private static final byte[] TEST_APPLET1_AID_BYTES = Hex.decode("01020304050607080A");
    private static final AID appletAID = new AID(TEST_APPLET1_AID_BYTES, (short) 0, (byte) TEST_APPLET1_AID_BYTES.length);

    static JavaxSmartCardInterface createInterface() {
        JavaxSmartCardInterface sim = new JavaxSmartCardInterface();
        sim.installApplet(appletAID, EPApplet.class);
        sim.selectApplet(appletAID);

        return sim;
    }

    static ResponseAPDU createAndSendCommand(JavaxSmartCardInterface sim, byte cla, byte ins, byte p1, byte p2, byte[] data) {
        CommandAPDU c1 = new CommandAPDU(cla, ins, p1, p2, data);
        return sim.transmitCommand(c1);
    }

    static RSAPublicKey runInit(JavaxSmartCardInterface sim) {
        byte cla = -1;
        byte p1 = 0;
        byte p2 = 0;

        byte[] data1 = new byte[14];

        Util.setShort(data1, (short) 0, (short) 1); // cardNumber
        Util.setShort(data1, (short) 2, (short) 2); // balance
        Util.setShort(data1, (short) 4, (short) 3); // pin
        Util.setShort(data1, (short) 6, (short) 4); // softLimit
        Util.setShort(data1, (short) 8, (short) 5); // hardLimit

        ResponseAPDU r = TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, data1);

        RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);
        KeyHelper.init(key, r.getData(), (short) 1);

        return key;
    }

    static void runAuth(JavaxSmartCardInterface sim, byte cla) {
        byte p1 = 0;
        byte p2 = 0;

        // check card number
        byte[] data1 = new byte[]{0, 4};
        TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, data1);

        // check pin
        byte[] data2 = new byte[]{0, 0};
        Util.setShort(data2, (short) 0, (short) 0);
        TestHelper.createAndSendCommand(sim, cla, (byte) 1, p1, p2, data2);
    }

    static KeyPair createKeyPairRsa() {
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();

        return keyPair;
    }

    static byte[] writePkRsa(RSAPublicKey pb, byte[] buffer, short offset) {
        short expSize = pb.getExponent(buffer, (short) (offset + 4));
        short modSize = pb.getModulus(buffer, (short) (offset + expSize + 4));

        Util.setShort(buffer, (short) offset, expSize);
        Util.setShort(buffer, (short) (offset + 2), modSize);

        return buffer;
    }

    static short encryptRsa(Key key, byte[] buffer, short msgSize) {
        byte[] decryptBuffer = new byte[255];
        Util.arrayCopy(buffer, (short) 0, decryptBuffer, (short) 0, msgSize);

        Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        rsaCipher.init(key, Cipher.MODE_ENCRYPT);

        return rsaCipher.doFinal(decryptBuffer, (short) 0, msgSize, buffer, (short) 0);
    }

    static byte[] decryptRsa(PrivateKey key, byte[] buffer) {
        byte[] decryptBuffer = new byte[255];

        Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        rsaCipher.init(key, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(buffer, (short) 0, (short) buffer.length, decryptBuffer, (short) 0);

        return decryptBuffer;
    }

    static AESKey createKeyAes() {
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(keyBufferAes(), (short) 0);

        return aesKey;
    }

    static byte[] keyBufferAes() {
        return new byte[]{0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d};
    }

    static byte[] encryptAes(AESKey key, byte[] buffer, short msgLength) {
        byte[] ivdata = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        random.generateData(ivdata, (short) 0, (short) 16);

        short encLength = (short) (getBlockSize((short) (msgLength + 2)) * 16);

        byte[] encryptBuffer = new byte[encLength];
        byte[] encTarget = new byte[encLength + 2 + 16];

        Util.setShort(encryptBuffer, (short) 0, msgLength);
        Util.arrayCopy(buffer, (short) 0, encryptBuffer, (short) 2, msgLength);

        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(key, Cipher.MODE_ENCRYPT, ivdata, (short) 0, (short) 16);
        aesCipher.doFinal(encryptBuffer, (short) 0, encLength, encTarget, (short) 2);

        Util.setShort(encTarget, (short) 0, encLength);
        Util.arrayCopy(ivdata, (short) 0, encTarget, (short) (encLength + 2), (short) ivdata.length);

        return encTarget;
    }

    static byte[] decryptAes(AESKey key, byte[] buffer) {
        byte[] ivdata = new byte[16];
        byte[] decryptBuffer = new byte[250];

        short encSize = Util.getShort(buffer, (short) 0);

        Util.arrayCopy(buffer, (short) 2, decryptBuffer, (short) 0, encSize);
        Util.arrayCopy(buffer, (short) (encSize + 2), ivdata, (short) 0, (short) 16);

        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(key, Cipher.MODE_DECRYPT, ivdata, (short) 0, (short) 16);
        aesCipher.doFinal(decryptBuffer, (short) 0, encSize, buffer, (short) 0);

        return buffer;
    }

    private static short getBlockSize(short msgSize) {
        short blocks = (short) (msgSize / 16);
        if ((msgSize % 16) > 0)
            blocks++;

        return blocks;
    }

}
