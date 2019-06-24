package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.RSAPublicKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.assertEquals;

public class ChangePinTest {

    private static final byte CLA = (byte) 0xd1;

    @Test
    public void testSuccess1() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        Object[] objs = TestHelper.runAuth(sim, CLA, (short) 40);
        AESKey aesKey = (AESKey) objs[0];
        RSAPublicKey pkCard = (RSAPublicKey) objs[1];

        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 40); // nonce
        Util.setShort(buffer, (short) 2, (short) 1234); // pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 3, p1, p2, buffer);

        byte[] respData = TestHelper.decryptAes(aesKey, r.getData());
        byte[] respData2 = TestHelper.decryptRsa(pkCard, respData);

        short nonce = Util.getShort(respData2, (short) 1);
        short log = Util.getShort(respData2, (short) 3);

        assertEquals("Incorrect r cla", CLA, respData2[0]);
        assertEquals("Incorrect r nonce", 40, nonce);
        assertEquals("Incorrect r returned log", Log.PIN_CHANGED, log);
        assertEquals("Incorrect r SW", 36864, r.getSW());
    }
}
