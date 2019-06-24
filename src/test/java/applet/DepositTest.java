package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RSAPublicKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class DepositTest {

    private static final byte CLA = (byte) 0xd4;

    @Test
    public void testSuccess() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuthNoPin(sim, CLA, (short) 50);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        // check card number
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 50); // nonce
        Util.setShort(buffer, (short) 2, (short) 5000); // deposit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        short nonce = Util.getShort(respData2, (short) 1);
        short balance = Util.getShort(respData2, (short) 3);
        short log = Util.getShort(respData2, (short) 5);

        assertEquals("Incorrect r cla", CLA, respData2[0]);
        assertEquals("Incorrect r nonce", 50, nonce);
        assertEquals("Incorrect r balance", 5020, balance); // default amount is 20
        assertEquals("Incorrect r log", Log.DEPOSIT_COMPLETED, log);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

}
