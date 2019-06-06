//package applet;
//
//import javacard.framework.*;
//
//public class EPApplet2 extends Applet implements ISO7816 {
//
//    private static final byte PIN_TRY_LIMIT = 3;
//    private static final byte MAX_PIN_SIZE = 4;
//
//    private short cardNumber;
//
//    private OwnerPIN pin;
//    private byte[] dummyPinRemoveLater = {0, 0};
//
//    private short balance;
//    private short paymentAmount;
//
//    private short totalToday;
//
//    private short softLimit;
//    private short hardLimit;
//
//    // We assume card is ejected after completed interaction and these values get reset
//    private short claCounter;
//    private short insCounter;
//
//    public static void install(byte[] buffer, short offset, byte length)
//            throws SystemException {
//        new EPApplet();
//    }
//
//    public EPApplet2() {
//        cardNumber = 4;
//        balance = 4000;
//
//        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
//        pin.update(dummyPinRemoveLater, (byte) 0, (byte) 2);
//
//        softLimit = 2000;
//        hardLimit = 10000;
//        register();
//    }
//
//    @Override
//    public boolean select() {
//        resetCounters();
//        return true;
//    }
//
//    public void process(APDU apdu) throws ISOException {
//        byte[] buffer = apdu.getBuffer();
//        byte cla = buffer[OFFSET_CLA];
//        byte ins = buffer[OFFSET_INS];
//
//        if (selectingApplet()) // we ignore this, it makes ins = -92
//            return;
//
//        if (validCounters(cla, ins)) {
//            claCounter = cla;
//        } else {
//            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
//            return;
//        }
//
//        switch (cla) {
//            case -1:
//                initialize(apdu);
//                break;
//            case 0:
//                changePinMain(apdu);
//                break;
//            case 1: // Change soft limit
//                changeSoftLimitMain(apdu);
//                break;
//            case 2: // Payment, so balance decrease
//                payment(apdu);
//                break;
//            case 3: // Deposit, so balance increase
//                deposit(apdu);
//                break;
//            default:
//                ISOException.throwIt(SW_CLA_NOT_SUPPORTED);
//                break;
//        }
//    }
//
//    //<editor-fold desc="Initialize">
//
//    private void initialize(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//
//        cardNumber = Util.getShort(buffer, (short) 4);
//        balance = Util.getShort(buffer, (short) 6);
//        softLimit = Util.getShort(buffer, (short) 10);
//        hardLimit = Util.getShort(buffer, (short) 12);
//
//        pin.update(buffer, (short) 8, (byte) 2);
//        resetCounters();
//    }
//
//    //</editor-fold>
//
//    //<editor-fold desc="Change PIN">
//
//    private void changePinMain(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        byte ins = buffer[OFFSET_INS];
//
//        switch (ins) {
//            case 0: // respond with card number
//                respondWithCardNumber(apdu);
//                break;
//            case 1: // check pin
//                checkPin(apdu);
//                break;
//            case 2:
//                changePin(apdu);
//                break;
//            default:
//                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
//                break;
//        }
//    }
//
//    private void changePin(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//
//        pin.update(buffer, OFFSET_CDATA, (byte) 2);
//        resetCounters();
//
//        buffer[1] = 1; // set status code
//        sendResponse(apdu, (short) 2);
//    }
//
//    //</editor-fold>
//
//    //<editor-fold desc="Change Soft limit">
//
//    private void changeSoftLimitMain(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        byte ins = buffer[OFFSET_INS];
//
//        switch (ins) {
//            case 0: // respond with card number
//                respondWithCardNumber(apdu);
//                break;
//            case 1: // check pin
//                checkPin(apdu);
//                break;
//            case 2:
//                changeSoftLimit(apdu);
//                break;
//            default:
//                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
//                break;
//        }
//    }
//
//    private void changeSoftLimit(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        byte statusCode;
//
//        short newSoftLimit = Util.getShort(buffer, OFFSET_CDATA);
//        if (newSoftLimit > hardLimit) {
//            statusCode = -1;
//        } else {
//            statusCode = 1;
//            softLimit = newSoftLimit;
//        }
//
//        buffer[1] = statusCode; // set status code
//        Util.setShort(buffer, (short) 2, softLimit);
//        sendResponse(apdu, (short) 4);
//    }
//
//    //</editor-fold>
//
//    //<editor-fold desc="Payment">
//
//    private void payment(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        byte ins = buffer[OFFSET_INS];
//
//        switch (ins) {
//            case 0: // respond with card number
//                respondWithCardNumber(apdu);
//                break;
//            case 1: // check soft limit
//                checkSoftLimit(apdu);
//                break;
//            case 2: // check pin
//                checkPin(apdu);
//                break;
//            case 3: // decrease balance
//                decreaseBalance(apdu);
//                break;
//            default:
//                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
//                break;
//        }
//    }
//
//    private void checkSoftLimit(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//
//        paymentAmount = Util.getShort(buffer, OFFSET_CDATA);
//        byte statusCode;
//
//        if (balance < paymentAmount) {
//            statusCode = -1;
//            resetCounters();
//
//        } else if (paymentAmount > softLimit) {
//            statusCode = -2;
//            insCounter++;
//
//        } else if (paymentAmount + totalToday > hardLimit) {
//            statusCode = -3;
//            resetCounters();
//
//        } else {
//            statusCode = 1;
//            insCounter += 2;
//        }
//
//        buffer[1] = statusCode;
//        sendResponse(apdu, (short) 2);
//    }
//
//    private void decreaseBalance(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        balance -= paymentAmount;
//
//        resetCounters();
//
//        Util.setShort(buffer, (short) 1, balance);
//        sendResponse(apdu, (short) 3);
//    }
//
//    //</editor-fold>
//
//    //<editor-fold desc="Deposit">
//
//    private void deposit(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        byte ins = buffer[OFFSET_INS];
//
//        switch (ins) {
//            case 0: // respond with card number
//                respondWithCardNumber(apdu);
//                break;
//            case 1: // increase balance
//                increaseBalance(apdu);
//                break;
//            default:
//                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
//                break;
//        }
//    }
//
//    private void increaseBalance(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//        short amount = Util.getShort(buffer, OFFSET_CDATA);
//        balance += amount;
//
//        resetCounters();
//
//        Util.setShort(buffer, (short) 1, balance);
//        sendResponse(apdu, (short) 3);
//    }
//
//    //</editor-fold>
//
//    private void respondWithCardNumber(APDU apdu) {
//        insCounter++;
//
//        Util.setShort(apdu.getBuffer(), (short) 1, cardNumber);
//        sendResponse(apdu, (short) 3);
//    }
//
//    private void checkPin(APDU apdu) {
//        byte[] buffer = apdu.getBuffer();
//
//        boolean correctPin = pin.check(buffer, OFFSET_CDATA, (byte) 2);
//        byte statusCode;
//
//        if (correctPin) {
//            insCounter++;
//            pin.reset();
//
//            statusCode = 1;
//        } else {
//            statusCode = -1;
//        }
//
//        buffer[1] = statusCode;
//        sendResponse(apdu, (short) 2);
//    }
//
//    private void sendResponse(APDU apdu, short length) {
//        apdu.setOutgoingAndSend((short) 0, length);
//    }
//
//    private boolean validCounters(byte cla, byte ins) {
//        if (claCounter != -1 && claCounter != cla)
//            return false;
//
//        if (insCounter + 1 != ins)
//            return false;
//
//        return true;
//    }
//
//    private void resetCounters() {
//        claCounter = -1;
//        insCounter = -1;
//    }
//
//}
