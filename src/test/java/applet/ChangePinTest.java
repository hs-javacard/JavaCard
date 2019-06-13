package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class ChangePinTest {

    private static final byte CLA = 0;

    @Test
    public void testSuccess1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        AESKey aesKey = TestHelper.runAuth(sim, CLA);

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 41); // nonce
        Util.setShort(buffer, (short) 2, (short) 1234); // pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        short nonce = Util.getShort(respData, (short) 1);

        assertEquals("Incorrect r cla", CLA, respData[0]);
        assertEquals("Incorrect r status code", 1, respData[3]);
        assertEquals("Incorrect r nonce", 41, nonce);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }
}
