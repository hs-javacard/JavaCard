package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class EPApplet extends Applet implements ISO7816 {

    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte MAX_PIN_SIZE = 4;

    private RSAPublicKey pkTerminal;
    private KeyPair keyPair;
    private AESKey aesKey;

    private OwnerPIN pin;

    private Cipher rsaCipher;
    private Cipher aesCipher;

    private byte[] rsaWorkspace;
    private byte[] aesWorkspace;

    private RandomData random;

    private byte[] ivdata;
    private byte[] aesKeyBuffer = {0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d};

    private short cardNumber;

    private short balance;
    private short paymentAmount;

    private short dayNumber;
    private short totalToday;

    private short softLimit;
    private short hardLimit;

    private short nonce;

    // We assume card is ejected after completed interaction and these values get reset
    private byte claCounter;
    private byte insCounter;

    public static void install(byte[] buffer, short offset, byte length)
            throws SystemException {
        new EPApplet();
    }

    public EPApplet() {

        try {
            keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            keyPair.genKeyPair();
        } catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }

        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        rsaWorkspace = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
        aesWorkspace = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        ivdata = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
//        aesKeyBuffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
//        aesKeyBuffer = {0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d};

        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        pkTerminal = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        register();
    }

    @Override
    public boolean select() {
        resetCounters();
        return true;
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];

        if (selectingApplet()) // we ignore this, it makes ins = -92
            return;

        if (validCounters(cla, ins)) {
            claCounter = cla;
        } else {
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        switch (cla) {
            case -1:
                initialize(apdu);
                break;
            case 0:
                changePinMain(apdu);
                break;
            case 1: // Change soft limit
                changeSoftLimitMain(apdu);
                break;
            case 2: // Payment, so balance decrease
                payment(apdu);
                break;
            case 3: // Deposit, so balance increase
                deposit(apdu);
                break;
            case 101:

                Util.arrayCopy("Henk!".getBytes(), (short) 0, buffer, (short) 0, (short) 5);

                short encSize = encryptAes(apdu, (short) 5);
                sendResponse(apdu, encSize);
                break;

            case 102:
                // get encrypted message, blocksize + {msgsize + msg}sk
                decryptAes(apdu);
                short len = Util.getShort(buffer, (short) 0);
//                short a = 0;
                sendResponse(apdu, (short) (len + 2));
                // return plain text for now
                break;
            default:
                ISOException.throwIt(SW_CLA_NOT_SUPPORTED);
                break;
        }
    }

    //<editor-fold desc="Initialize">

    private void initialize(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0:
                setInitData(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }

    }

    private void setInitData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte offset = OFFSET_CDATA;

        cardNumber = Util.getShort(buffer, (short) offset);
        balance = Util.getShort(buffer, (short) (offset + 2));
        softLimit = Util.getShort(buffer, (short) (offset + 6));
        hardLimit = Util.getShort(buffer, (short) (offset + 8));

        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(buffer, (short) (offset + 4), (byte) 2);

        resetCounters();
        sendPublicKey(apdu);
    }

    private void sendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        RSAPublicKey pb = (RSAPublicKey) keyPair.getPublic();
        short expSize = pb.getExponent(buffer, (short) 5);
        short modSize = pb.getModulus(buffer, (short) (expSize + 5));

        buffer[0] = claCounter;
        Util.setShort(buffer, (short) 1, expSize);
        Util.setShort(buffer, (short) 3, modSize);
        sendResponse(apdu, (short) (1 + expSize + modSize + 4));
    }

    //</editor-fold>

    //<editor-fold desc="Change PIN">

    private void changePinMain(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0: // respond with card number
                retrievePkTAndSendCardNumber(apdu);
                break;
            case 1:
                retrieveSymmetricKey(apdu);
                break;
            case 2: // check pin
                checkPin(apdu);
                break;
            case 3:
                changePin(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void changePin(APDU apdu) {
        byte[] buffer = decryptAes(apdu);

        pin.update(buffer, OFFSET_CDATA, (byte) 2);
        resetCounters();

        buffer[1] = 1; // set status code

        short length = encryptAes(apdu, (short) 2);
        sendResponse(apdu, length);
    }

    //</editor-fold>

    //<editor-fold desc="Change Soft limit">

    private void changeSoftLimitMain(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0: // respond with card number
                retrievePkTAndSendCardNumber(apdu);
                break;
            case 1:
                retrieveSymmetricKey(apdu);
                break;
            case 2: // check pin
                checkPin(apdu);
                break;
            case 3:
                changeSoftLimit(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void changeSoftLimit(APDU apdu) {
        byte[] buffer = decryptAes(apdu);
        byte statusCode;

        short newSoftLimit = Util.getShort(buffer, OFFSET_CDATA);
        if (newSoftLimit > hardLimit) {
            statusCode = -1;
        } else {
            statusCode = 1;
            softLimit = newSoftLimit;
        }

        buffer[1] = statusCode; // set status code
        Util.setShort(buffer, (short) 2, softLimit);

        short length = encryptAes(apdu, (short) 4);
        sendResponse(apdu, length);
    }

    //</editor-fold>

    //<editor-fold desc="Payment">

    private void payment(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0: // respond with card number
                retrievePkTAndSendCardNumber(apdu);
                break;
            case 1:
                retrieveSymmetricKey(apdu);
                break;
            case 2: // check soft limit
                checkSoftLimit(apdu);
                break;
            case 3: // check pin
                checkPin(apdu);
                break;
            case 4: // decrease balance
                decreaseBalance(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void checkSoftLimit(APDU apdu) {
        byte[] buffer = decryptAes(apdu);
        checkNonce(buffer);

        paymentAmount = Util.getShort(buffer, OFFSET_CDATA);
        short dayNumber = Util.getShort(buffer, (short) (OFFSET_CDATA + 2));
        if (this.dayNumber != dayNumber)
            totalToday = 0;

        byte statusCode;

        if (balance < paymentAmount) {
            statusCode = -1;
            resetCounters();

        } else if (paymentAmount > softLimit) {
            statusCode = -2;
            insCounter++;

        } else if (paymentAmount + totalToday > hardLimit) {
            statusCode = -3;
            resetCounters();

        } else {
            totalToday += paymentAmount;

            statusCode = 1;
            insCounter += 2;
        }

        buffer[1] = statusCode;

        short length = encryptAes(apdu, (short) 2);
        sendResponse(apdu, length);
    }

    private void decreaseBalance(APDU apdu) {
        byte[] buffer = decryptAes(apdu);
        balance -= paymentAmount;

        resetCounters();

        Util.setShort(buffer, (short) 1, balance);

        short length = encryptAes(apdu, (short) 3);
        sendResponse(apdu, length);
    }

    //</editor-fold>

    //<editor-fold desc="Deposit">

    private void deposit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0: // respond with card number
                retrievePkTAndSendCardNumber(apdu);
                break;
            case 1:
                retrieveSymmetricKey(apdu);
                break;
            case 2: // increase balance
                increaseBalance(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void increaseBalance(APDU apdu) {
        byte[] buffer = decryptAes(apdu);
        short amount = Util.getShort(buffer, OFFSET_CDATA);
        balance += amount;

        resetCounters();

        Util.setShort(buffer, (short) 1, balance);

        short length = encryptAes(apdu, (short) 3);
        sendResponse(apdu, length);
    }

    //</editor-fold>

    private void retrievePkTAndSendCardNumber(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        nonce = Util.getShort(buffer, OFFSET_CDATA);
        KeyHelper.init(pkTerminal, buffer, (short) (OFFSET_CDATA + 2));

        insCounter++;

        buffer[0] = claCounter;
        Util.setShort(buffer, (short) 1, nonce);
        Util.setShort(buffer, (short) 3, cardNumber);

        short length = encryptRsa(apdu, (short) 5, pkTerminal);
        sendResponse(apdu, length);
    }

//    public void retrievePkTAndSendCardNumber(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
////        nonce = Util.getShort(buffer, OFFSET_CDATA);
//        KeyHelper.init(pkTerminal, buffer, (short) (OFFSET_CDATA + 0));
//
//        insCounter++;
//
//        Util.arrayCopy("Henk2".getBytes(), (short) 0, buffer, (short) 0, (short) 5);
////        buffer[0] = claCounter;
////        Util.setShort(buffer, (short) 1, nonce);
////        Util.setShort(buffer, (short) 3, cardNumber);
//
//        short length = encryptRsa(apdu, (short) 5, pkTerminal);
//        sendResponse(apdu, (short) length);
//    }

    private void retrieveSymmetricKey(APDU apdu) {
        byte[] buffer = decryptRsa(apdu);

        checkNonce(buffer);
        initSymmetricKey(buffer);

        buffer[0] = claCounter;
        Util.setShort(buffer, (short) 1, nonce);

        insCounter++;

        short length = encryptAes(apdu, (short) 3);
        sendResponse(apdu, length);
    }

    private void initSymmetricKey(byte[] buffer) {
        Util.arrayCopy(buffer, (short) 0, aesKeyBuffer, (short) 0, (short) 16);
        aesKey.setKey(aesKeyBuffer, (short) 0);
    }

    private void checkPin(APDU apdu) {
        byte[] buffer = decryptAes(apdu);
        checkNonce(buffer);

        boolean correctPin = pin.check(buffer, (short) (OFFSET_CDATA + 2), (byte) 2);
        byte statusCode;

        if (correctPin) {
            insCounter++;
            pin.reset();

            statusCode = 1;
        } else {
            statusCode = -1;
        }

        buffer[0] = claCounter;
        buffer[3] = statusCode;
        Util.setShort(buffer, (short) 1, nonce);

        //ENCRYPT HERE
        short length = encryptAes(apdu, (short) 4);
        sendResponse(apdu, length);
    }

    private void checkNonce(byte[] buffer) {
        short nonce = Util.getShort(buffer, OFFSET_CDATA);
        if (this.nonce == nonce) {
            ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
        } else {
            this.nonce = nonce;
        }
    }

    //<editor-fold desc="Counters">

    private boolean validCounters(byte cla, byte ins) {
        if (claCounter != -1 && claCounter != cla)
            return false;

        if (insCounter + 1 != ins)
            return false;

        return true;
    }

    private void resetCounters() {
        claCounter = -1;
        insCounter = -1;
    }

    //</editor-fold>

    //<editor-fold desc="RSA">

    private byte[] decryptRsa(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(buffer, (short) OFFSET_CDATA, rsaWorkspace, (short) 0, (short) 128);

        RSAPrivateKey pk = (RSAPrivateKey) keyPair.getPrivate();
        rsaCipher.init(pk, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(rsaWorkspace, (short) 0, (short) 128, buffer, (short) 0);

        return buffer;
    }

    private short encryptRsa(APDU apdu, short msgSize, Key key) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(buffer, (short) 0, rsaWorkspace, (short) 0, msgSize);

        rsaCipher.init(key, Cipher.MODE_ENCRYPT);
        return rsaCipher.doFinal(rsaWorkspace, (short) 0, msgSize, buffer, (short) 0);
    }

    //</editor-fold>

    //<editor-fold desc="AES">

    private short encryptAes(APDU apdu, short msgSize) {
        byte[] buffer = apdu.getBuffer();

        Util.arrayCopy(buffer, (short) 0, aesWorkspace, (short) 2, msgSize);

        short blocks = getBlockSize((short) (msgSize + 2));
        short encSize = (short) (blocks * 16);
        short paddingSize = (short) (encSize - msgSize);

        Util.arrayFillNonAtomic(aesWorkspace, (short) (msgSize + 2), paddingSize, (byte) 3);
        Util.setShort(aesWorkspace, (short) 0, msgSize);
        // generate IV
        random.generateData(ivdata, (short) 0, (short) 16);

        aesKey.setKey(aesKeyBuffer, (short) 0); // Should be done after receiving

        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT, ivdata, (short) 0, (short) 16);
        aesCipher.doFinal(aesWorkspace, (short) 0, encSize, buffer, (short) 2);

        short offset = 16 + 2;

        Util.arrayCopy(ivdata, (short) 0, buffer, offset, (short) 16);
        Util.setShort(buffer, (short) 0, encSize);

        return (short) (encSize + 2 + 16);
    }

    private byte[] decryptAes(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short encSize = Util.getShort(buffer, (short) OFFSET_CDATA);

        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + 2), aesWorkspace, (short) 0, encSize);
        Util.arrayCopy(buffer, (short) (OFFSET_CDATA + encSize + 2), ivdata, (short) 0, (short) 16);

        aesKey.setKey(aesKeyBuffer, (short) 0);
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT, ivdata, (short) 0, (short) 16);
        aesCipher.doFinal(aesWorkspace, (short) 0, encSize, buffer, (short) 0);

        return buffer;
    }

    private short getBlockSize(short msgSize) {
        short blocks = (short) (msgSize / 16);
        if ((msgSize % 16) > 0)
            blocks++;

        return blocks;
    }

    //</editor-fold>

    private void sendResponse(APDU apdu, short length) {
        apdu.setOutgoingAndSend((short) 0, length);
    }

}
