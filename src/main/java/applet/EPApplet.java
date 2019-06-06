package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class EPApplet extends Applet implements ISO7816 {

    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte MAX_PIN_SIZE = 4;

    private RSAPublicKey pkTerminal;
    private KeyPair keyPair;
    private Cipher rsaCipher;

    private byte[] buffer1;
    private byte[] buffer2;

    private OwnerPIN pin;

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

        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        pkTerminal = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);

        buffer1 = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
        buffer2 = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);

        cardNumber = 4;
        balance = 4000;
        softLimit = 2000;
        hardLimit = 10000;
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

        decrypt(apdu);

        if (ins == 0)
            initTerminalKey(apdu);

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
        short expSize = pb.getExponent(buffer, (short) 4);
        short modSize = pb.getModulus(buffer, (short) (expSize + 4));

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
            case 1: // check pin
                checkPin(apdu);
                break;
            case 2:
                changePin(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void changePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        pin.update(buffer, OFFSET_CDATA, (byte) 2);
        resetCounters();

        buffer[1] = 1; // set status code
        sendResponse(apdu, (short) 2);
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
        byte[] buffer = apdu.getBuffer();
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
        sendResponse(apdu, (short) 4);
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
        byte[] buffer = apdu.getBuffer();
        retrieveNonce(buffer);

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
        sendResponse(apdu, (short) 2);
    }

    private void decreaseBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        balance -= paymentAmount;

        resetCounters();

        Util.setShort(buffer, (short) 1, balance);
        sendResponse(apdu, (short) 3);
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
        byte[] buffer = apdu.getBuffer();
        short amount = Util.getShort(buffer, OFFSET_CDATA);
        balance += amount;

        resetCounters();

        Util.setShort(buffer, (short) 1, balance);
        sendResponse(apdu, (short) 3);
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

        //ENCRYPT HERE
        sendResponse(apdu, (short) 5);
    }

    private void retrieveSymmetricKey(APDU apdu) {
        //DECRYPT HERE
        byte[] buffer = apdu.getBuffer();
        retrieveNonce(buffer);

        //SET SYSTEM KEY

        buffer[0] = claCounter;
        Util.setShort(buffer, (short) 1, nonce);

        //ENCRYPT HERE
        sendResponse(apdu, (short) 3);
    }

    private void checkPin(APDU apdu) {
        //DECRYPT AES HERE
        byte[] buffer = apdu.getBuffer();
        retrieveNonce(buffer);

        //DECRYPT RSA HERE
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
        buffer[1] = statusCode;

        //ENCRYPT HERE
        sendResponse(apdu, (short) 2);
    }

    private void sendResponse(APDU apdu, short length) {
        apdu.setOutgoingAndSend((short) 0, length);
    }

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

    private void retrieveNonce(byte[] buffer) {
        nonce = Util.getShort(buffer, OFFSET_CDATA);
    }

    private void initTerminalKey(APDU apdu) {
        KeyHelper.init(pkTerminal, buffer1, (short) 0);
    }

    public void decrypt(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        RSAPrivateKey pk = (RSAPrivateKey) keyPair.getPrivate();
        rsaCipher.init(pk, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(buffer, (short) OFFSET_CDATA, (short) 128, buffer1, (short) 0);
    }

    public void encrypt(Key key, byte[] from, byte[] to) {
        rsaCipher.init(key, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(from, (short) 0, (short) from.length, to, (short) 0);
    }

}
