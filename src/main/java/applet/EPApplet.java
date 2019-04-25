package applet;

import javacard.framework.*;

public class EPApplet extends Applet implements ISO7816 {

    private short cardNumber;
    private short pin;

    private short balance;

    private short totalToday;

    private short softLimit;
    private short hardLimit;

    public static void install(byte[] buffer, short offset, byte length)
            throws SystemException {
        new EPApplet();
    }

    public EPApplet() {
        cardNumber = 4;
        pin = 0;
        balance = 1950;

        softLimit = 2000;
        hardLimit = 20000;
        register();
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[OFFSET_CLA];

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
        byte statusCode = this.pin == pin
                ? (byte) 1
                : (byte) -1;

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
