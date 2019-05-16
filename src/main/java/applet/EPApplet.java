package applet;

import javacard.framework.*;

public class EPApplet extends Applet implements ISO7816 {

    private static final byte PIN_TRY_LIMIT = 3;
    private static final byte MAX_PIN_SIZE = 4;

    private short cardNumber;

    private OwnerPIN pin;
    private byte[] dummyPinRemoveLater = {0, 0};

    private short balance;
    private short paymentAmount;

    private short totalToday;

    private short softLimit;
    private short hardLimit;

    // We assume card is ejected after completed interaction and these values get reset
    private short claCounter;
    private short insCounter;

    public static void install(byte[] buffer, short offset, byte length)
            throws SystemException {
        new EPApplet();
    }

    public EPApplet() {
        cardNumber = 4;
        balance = 4000;

        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(dummyPinRemoveLater, (byte) 0, (byte) 2);

        softLimit = 2000;
        hardLimit = 20000;
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
            case 0: // Authenticate
                auth(apdu);
                break;
            case 1: // Change soft limit
                changeSoftLimit(apdu);
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

    //<editor-fold desc="Auth">

    private void auth(APDU apdu) {
    }

    //</editor-fold>

    //<editor-fold desc="Change Soft limit">

    private void changeSoftLimit(APDU apdu) {
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

    private void sendResponse(APDU apdu, short length) {
        apdu.setOutgoingAndSend((short) 0, length);
    }

}
