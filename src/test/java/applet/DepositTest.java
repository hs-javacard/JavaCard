package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class DepositTest {

    private static final byte CLA = 3;

    @Test
    public void testSuccess() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        AESKey aesKey = TestHelper.runAuthNoPin(sim, CLA);

        // check card number
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 51); // nonce
        Util.setShort(buffer, (short) 2, (short) 5000); // deposit

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);
        short balance = Util.getShort(respData, (short) 3);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r nonce", 51, nonce);
        assertEquals("Incorrect r balance", 5020, balance); // default amount is 20
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }

}
