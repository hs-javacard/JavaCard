package applet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;
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

        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();

        byte[] buffer = new byte[255];
        byte[] decryptBuffer = new byte[255];

        RSAPublicKey pb = (RSAPublicKey) keyPair.getPublic();
        short expSize = pb.getExponent(buffer, (short) 4);
        short modSize = pb.getModulus(buffer, (short) (expSize + 4));

        Util.setShort(buffer, (short) 0, expSize);
        Util.setShort(buffer, (short) 2, modSize);

        CommandAPDU c6 = new CommandAPDU(1, 0, p1, p2, buffer);
        ResponseAPDU r6 = sim.transmitCommand(c6);

        byte[] keyBuffer = r6.getData();

        System.out.println(pb.isInitialized());

        Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        rsaCipher.init(pb, Cipher.MODE_DECRYPT);

        rsaCipher.doFinal(keyBuffer, (short) 0, (short) keyBuffer.length, decryptBuffer, (short) 0);

        System.out.println(new String(decryptBuffer));

    }

}
