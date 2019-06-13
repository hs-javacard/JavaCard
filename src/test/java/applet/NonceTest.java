package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.AESKey;
import org.junit.Test;

import javax.smartcardio.ResponseAPDU;

import static javacard.framework.ISO7816.SW_COMMAND_NOT_ALLOWED;
import static org.junit.Assert.assertEquals;

public class NonceTest {

    private static final byte CLA = 0;

    @Test
    public void testFail() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte p1 = 0;
        byte p2 = 0;

        AESKey aesKey = TestHelper.runAuthNoPin(sim, CLA);

        // Incorrect pin
        byte[] buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 13); //nonce
        Util.setShort(buffer, (short) 2, (short) 9999); //pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        // Incorrect pin
        buffer = new byte[255];
        Util.setShort(buffer, (short) 0, (short) 13); //nonce
        Util.setShort(buffer, (short) 2, (short) 9999); //pin

        TestHelper.encryptAes(aesKey, buffer, (short) 4);
        ResponseAPDU r = TestHelper.createAndSendCommand(sim, CLA, (byte) 2, p1, p2, buffer);

        assertEquals("Incorrect r data size", 0, r.getData().length);
        assertEquals("Incorrect r SW", SW_COMMAND_NOT_ALLOWED, TestHelper.hexToDecimal(r.getSW()));
    }

}
