package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;
//import javacard.framework.OwnerPIN;


public class EPApplet extends Applet implements ISO7816 {

    private final static byte PIN_TRY_LIMIT = 3;
    private final static byte MAX_PIN_SIZE = 4;
    private short cardNumber;
    private OwnerPIN pin;
    private KeyPair keyPair;

    Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
    private byte[] dummyPinRemoveLater = {0,5};

    private byte[] decryptArray;

    private short balance;

    private short totalToday;

    private short softLimit;
    private short hardLimit;

    public static void install(byte[] buffer, short offset, byte length)
            throws SystemException {
        new EPApplet();
    }

    public EPApplet() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);


        try {
            keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
            keyPair.genKeyPair();
        } catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }

        decryptArray = JCSystem.makeTransientByteArray( (short) 128, JCSystem.CLEAR_ON_DESELECT);
        pin.update(dummyPinRemoveLater,(byte) 0,(byte) 2);

        pin.resetAndUnblock();
        cardNumber = 4;
//        pin = 0;
        balance = 1950;

        softLimit = 1000;
        hardLimit = 20000;
        register();
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];
        byte ins = buffer[OFFSET_INS];


        if (selectingApplet()) { // we ignore this, it makes ins = -92
            return;
        }

        switch (cla) {
            case 0: // Authenticate
                auth(apdu);
                break;
            case 1: // Change soft limit
                changeSoftLim(apdu);
                break;
            case 2: // Withdrawal
                withdrawal(apdu);
                break;
            case 100:
                switch (ins) {
                    case 0:
                    RSAPublicKey pb = (RSAPublicKey) keyPair.getPublic();
//                short pbSize = pb.getSize();
                    short expSize = pb.getExponent(buffer, (short) 4);

                    short modSize = pb.getModulus(buffer, (short) (expSize + 4));
//                Util.arrayCopy(,0,buffer,0,pbSize);
//                Util.setShort(buffer, (short) 0, (short) pbSize);
                    Util.setShort(buffer, (short) 0, expSize);
                    Util.setShort(buffer, (short) 2, modSize);
                    sendResponse(apdu, (short) (expSize + modSize + 4));
                    break;
                    case 1:
                        RSAPrivateKey pk = (RSAPrivateKey) keyPair.getPrivate();
                        rsaCipher.init(pk, Cipher.MODE_DECRYPT);
                        rsaCipher.doFinal(buffer, (short) OFFSET_CDATA, (short) 128, decryptArray, (short) 0);

                        int a = 0;
                        break;
                }
                break;
            default:
                ISOException.throwIt(SW_CLA_NOT_SUPPORTED);
                break;
        }
    }

    private void auth(APDU apdu) {
    }

    private void changeSoftLim(APDU apdu) {
    }

    private void withdrawal(APDU apdu) {
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
            case 3: // change balance
                changeBalance(apdu);
                break;
            default:
                ISOException.throwIt(SW_INCORRECT_P1P2);
                break;
        }
    }

    private void respondWithCardNumber(APDU apdu) {
        Util.setShort(apdu.getBuffer(), (short) 1, cardNumber);
        sendResponse(apdu, (short) 3);
    }

    private void checkSoftLimit(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short amount = Util.getShort(buffer, OFFSET_CDATA);
        byte statusCode;

        if (balance < amount) {
            statusCode = -1;
        } else if (amount > softLimit) {
            statusCode = -2;
        } else if (amount + totalToday > hardLimit) {
            statusCode = -3;
        } else {
            statusCode = 1;
        }

        buffer[1] = statusCode;
        sendResponse(apdu, (short) 2);
    }

    private void checkPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short pin = Util.getShort(buffer, OFFSET_CDATA);

        boolean valid = this.pin.check(buffer,OFFSET_CDATA,(byte) 2); // two bytes long

        byte statusCode = -1;
        if (valid) {
            statusCode = 1;
        }
//        byte statusCode = this.pin == pin
//                ? (byte) 1
//                : (byte) -1;

        buffer[1] = statusCode;
        sendResponse(apdu, (short) 2);
    }

    private void changeBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[OFFSET_P1];

        short amount = Util.getShort(buffer, OFFSET_CDATA);

        switch (p1) {
            case 0: // decrement balance
                balance -= amount;
                break;
            case 1: // increment balance
                balance += amount;
                break;
            default:
                ISOException.throwIt(SW_INCORRECT_P1P2);
                break;
        }

        Util.setShort(buffer, (short) 1, (short) 1);
        sendResponse(apdu, (short) 3);
    }

    private void sendResponse(APDU apdu, short length) {
        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytes((short) 0, length);
    }

}
