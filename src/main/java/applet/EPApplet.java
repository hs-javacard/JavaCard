package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class EPApplet extends Applet implements ISO7816 {

    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte MAX_PIN_SIZE = 4;

    private KeyPair keyPair;
    private Cipher rsaCipher;

    private RSAPublicKey pkTerminal;
    private RSAPublicKey pkBank;

    private byte[] decryptBuffer;
    private byte[] encryptBuffer;

    private OwnerPIN pin;
    private byte[] dummyPinRemoveLater = {0, 0};

    private short cardNumber;
    private short balance;
    private short paymentAmount;

    private short totalToday;

    private short softLimit;
    private short hardLimit;

    private short nonce;

    // We assume card is ejected after completed interaction and these values get reset
    private short claCounter;
    private short insCounter;

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

        decryptBuffer = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);

        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(dummyPinRemoveLater, (byte) 0, (byte) 2);

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
            setTerminalKey(apdu);

        setNonce(apdu);

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

    private void setNonce(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.setShort(buffer, (short) 0, (short) 2);
    }

    private void setTerminalKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        KeyHelper.init(pkTerminal, buffer, (short) 0);
    }

    public void decrypt(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        RSAPrivateKey pk = (RSAPrivateKey) keyPair.getPrivate();
        rsaCipher.init(pk, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(buffer, (short) OFFSET_CDATA, (short) 128, decryptBuffer, (short) 0);
    }

    public void encrypt(APDU apdu){
        rsaCipher.init(pkTerminal, Cipher.MODE_ENCRYPT);
        rsaCipher.doFinal(encryptBuffer, (short) 0,
                (short) encryptBuffer.length, apdu.getBuffer(), (short) 0);
    }

    //<editor-fold desc="Initialize">

    private void initialize(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0:
                setSkBank(apdu);
                break;
            case 1:
                setInitData(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }

    }

    private void setSkBank(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        KeyHelper.init(pkBank, buffer, (short) 0);
    }

    private void setInitData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        cardNumber = Util.getShort(buffer, (short) 4);
        balance = Util.getShort(buffer, (short) 6);
        softLimit = Util.getShort(buffer, (short) 10);
        hardLimit = Util.getShort(buffer, (short) 12);

        pin.update(buffer, (short) 8, (byte) 2);
        resetCounters();

        sendPublicKey(apdu);
    }

    private void sendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        RSAPublicKey pb = (RSAPublicKey) keyPair.getPublic();
        short expSize = pb.getExponent(buffer, (short) 4);
        short modSize = pb.getModulus(buffer, (short) (expSize + 4));

        Util.setShort(buffer, (short) 0, expSize);
        Util.setShort(buffer, (short) 2, modSize);
        sendResponse(apdu, (short) (expSize + modSize + 4));
    }

    //</editor-fold>

    //<editor-fold desc="Change PIN">

    private void changePinMain(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];

        switch (ins) {
            case 0: // respond with card number
                respondWithCardNumber(apdu);
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
                respondWithCardNumber(apdu);
                break;
            case 1: // check pin
                checkPin(apdu);
                break;
            case 2:
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
                respondWithCardNumber(apdu);
                break;
            case 1: // check soft limit
                checkSoftLimit(apdu);
                break;
            case 2: // check pin
                checkPin(apdu);
                break;
            case 3: // decrease balance
                decreaseBalance(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                break;
        }
    }

    private void checkSoftLimit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        paymentAmount = Util.getShort(buffer, OFFSET_CDATA);
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
                respondWithCardNumber(apdu);
                break;
            case 1: // increase balance
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

    private void respondWithCardNumber(APDU apdu) {
        insCounter++;

        Util.setShort(apdu.getBuffer(), (short) 1, cardNumber);
        sendResponse(apdu, (short) 3);
    }

    private void checkPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        boolean correctPin = pin.check(buffer, OFFSET_CDATA, (byte) 2);
        byte statusCode;

        if (correctPin) {
            insCounter++;
            pin.reset();

            statusCode = 1;
        } else {
            statusCode = -1;
        }

        buffer[1] = statusCode;
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

}
