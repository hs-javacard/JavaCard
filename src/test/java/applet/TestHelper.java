package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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
        Util.setShort(data1, (short) 2, (short) 20); // balance
        Util.setShort(data1, (short) 4, (short) 3); // pin
        Util.setShort(data1, (short) 6, (short) 5); // softLimit
        Util.setShort(data1, (short) 8, (short) 30); // hardLimit

        ResponseAPDU r = TestHelper.createAndSendCommand(sim, cla, (byte) 0, p1, p2, data1);

        RSAPublicKey key = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);
        KeyHelper.init(key, r.getData(), (short) 1);

        return key;
    }

    static Object[] runAuth(JavaxSmartCardInterface sim, byte cla) {
        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, cla);
        AESKey aesKey = (AESKey) objs[0];

        // Correct pin
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 13); //nonce
        Util.setShort(buffer, (short) 2, (short) 3); //pin

        encryptAes(aesKey, buffer, (short) 4);
        createAndSendCommand(sim, cla, (byte) 2, p1, p2, buffer);

        return objs;
    }

    static Object[] runAuthNoPin(JavaxSmartCardInterface sim, byte cla) {
        byte p1 = 0;
        byte p2 = 0;

        RSAPublicKey cardPk = runInit(sim);
        KeyPair keyPair = createKeyPairRsa();

        byte[] aesKeyBuffer = keyBufferAes();
        AESKey aesKey = createKeyAes();

        /////////////////////////////////////////////////////

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 11); //nonce
        writePkRsa((RSAPublicKey) keyPair.getPublic(), buffer, (short) 2);

        // check pkKeyTerminal number
        createAndSendCommand(sim, cla, (byte) 0, p1, p2, buffer);

        // set AES key
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 12); //nonce
        Util.arrayCopy(aesKeyBuffer, (short) 0, buffer, (short) 2, (short) 16); //aesKey

        encryptRsa(cardPk, buffer, (short) 18);
        createAndSendCommand(sim, cla, (byte) 1, p1, p2, buffer);

        return new Object[]{aesKey, cardPk};
    }

    static KeyPair createKeyPairRsa() {
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();

        return keyPair;
    }

    static byte[] writePkRsa(RSAPublicKey pb, byte[] buffer, short offset) {
        short expSize = pb.getExponent(buffer, (short) (offset + 4));
        short modSize = pb.getModulus(buffer, (short) (offset + expSize + 4));

        Util.setShort(buffer, offset, expSize);
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

    static byte[] decryptRsa(Key key, byte[] buffer) {
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

    static void encryptAes(AESKey key, byte[] buffer, short msgLength) {
        byte[] ivData = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        random.generateData(ivData, (short) 0, (short) 16);

        short encLength = (short) (getBlockSize(msgLength) * 16);

        byte[] encryptBuffer = new byte[encLength];

        Util.arrayCopy(buffer, (short) 0, encryptBuffer, (short) 0, msgLength);

        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(key, Cipher.MODE_ENCRYPT, ivData, (short) 0, (short) 16);
        aesCipher.doFinal(encryptBuffer, (short) 0, encLength, buffer, (short) 2);

        Util.setShort(buffer, (short) 0, encLength);
        Util.arrayCopy(ivData, (short) 0, buffer, (short) (encLength + 2), (short) ivData.length);
    }

    static byte[] decryptAes(AESKey key, byte[] buffer) {

        short encSize = Util.getShort(buffer, (short) 0);

        byte[] ivData = new byte[16];
        byte[] decryptBuffer = new byte[encSize];
        byte[] resultBuffer = new byte[encSize];

        Util.arrayCopy(buffer, (short) 2, decryptBuffer, (short) 0, encSize);
        Util.arrayCopy(buffer, (short) (encSize + 2), ivData, (short) 0, (short) 16);

        Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCipher.init(key, Cipher.MODE_DECRYPT, ivData, (short) 0, (short) 16);
        aesCipher.doFinal(decryptBuffer, (short) 0, encSize, resultBuffer, (short) 0);

        return resultBuffer;
    }

    private static short getBlockSize(short msgSize) {
        short blocks = (short) (msgSize / 16);
        if ((msgSize % 16) > 0)
            blocks++;

        return blocks;
    }

    static int hexToDecimal(int hex) {
        return Integer.parseInt(String.valueOf(hex), 10);
    }

}
