package applet;

//import com.licel.jcardsim.io.JavaxSmartCardInterface;
//import com.licel.jcardsim.smartcardio.CardSimulator;
//import com.licel.jcardsim.utils.AIDUtil;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
//import javacard.framework.APDU;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;
//import EPApplet;


public class EPAppletTest {


    private static final byte[] TEST_APPLET1_AID_BYTES = Hex.decode("01020304050607080A");
//    private static final String TEST_APPLET1_CLASSNAME = "com.licel.jcardsim.samples.HelloWorldApplet1";
    private static final AID appletAID = new AID(TEST_APPLET1_AID_BYTES, (short)0, (byte) TEST_APPLET1_AID_BYTES.length);


    @Test
    public void EPtest(){



        JavaxSmartCardInterface sim = new JavaxSmartCardInterface();
    sim.installApplet(appletAID, EPApplet.class);
//        sim.installApplet(appletAID, CalcApplet.class);


        sim.selectApplet(appletAID);


        byte cla = 0;
        byte ins = 0;
        byte p1 = 0;
        byte p2 = 0;
        byte[] data = new byte[] {3,4};
        byte len = 2;

        CommandAPDU c = new CommandAPDU(cla, ins, p1, p2, data, len);

        ResponseAPDU r = sim.transmitCommand(c);

        System.out.println("aa");
    }

@Test
public void test(){
//    APDU a = new APDU();
//    javacard.framework.

//    AID appletAID = AIDUtil();
//    AID appletAID = new AID(new byte[] {1},(short) 0,(byte) 1);





//    AID appletAID = new AIDUtil.create("F000000001");
//    AID appletAID = AIDUtil.create("F000000001");
//
//    CardSimulator sim = new CardSimulator();



    JavaxSmartCardInterface sim = new JavaxSmartCardInterface();
//    sim.installApplet(appletAID, EPApplet.class);
    sim.installApplet(appletAID, CalcApplet.class);


    sim.selectApplet(appletAID);


    byte cla = 0;
//    byte ins = (byte) 0;
    byte ins = (byte) '8';
    byte p1 = 0;
    byte p2 = 0;
    byte[] data = new byte[] {3,4};
    byte len = 2;

    CommandAPDU c = new CommandAPDU(cla, ins, p1, p2, data, len);
//    CommandAPDU();
//

    ResponseAPDU aaaaaa = sim.transmitCommand(c);
    CommandAPDU ca = new CommandAPDU(cla, '+', p1, p2, data, len);


    ResponseAPDU aaaaa2 = sim.transmitCommand(ca);
    CommandAPDU c2 = new CommandAPDU(cla, ins, p1, p2, data, len);

    ResponseAPDU aaaaa3 = sim.transmitCommand(c2);
    CommandAPDU ca2 = new CommandAPDU(cla, '=', p1, p2, data, len);
//    APDU a = c;


//    ResponseAPDU r = sim.transmitCommand(c);
//    ResponseAPDU r2 = sim.transmitCommand(ca);
//
//    String a = Arrays.toString(r2.getData());
//    System.out.println(a);
//    ResponseAPDU r3 = sim.transmitCommand(c);
//
    ResponseAPDU r4 = sim.transmitCommand(ca2);
//
//    String a2 = Arrays.toString(r4.getData());
//    System.out.println(a2);


//    EPApplet applet = new EPApplet();
//
//    applet.process(c);

    System.out.println("Oef");
}





}
