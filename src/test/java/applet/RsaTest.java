package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.Util;
import javacard.security.*;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class RsaTest {

    @Test
    public void EPtest() {
        JavaxSmartCardInterface sim = TestHelper.createInterface();

        byte cla = 1;
        byte p1 = 0;
        byte p2 = 0;

        byte[] buffer = new byte[255];

        KeyPair keyPair = TestHelper.createKeyPairRsa();
        TestHelper.writePkRsa((RSAPublicKey) keyPair.getPublic(), buffer, (short) 0);

        CommandAPDU c6 = new CommandAPDU(1, 0, p1, p2, buffer);
        ResponseAPDU r6 = sim.transmitCommand(c6);

        byte[] decryptBuffer = TestHelper.decryptRsa(keyPair.getPrivate(), r6.getData());
        System.out.println(new String(decryptBuffer));
    }

}
