package a.b;
public class d {
    public static void checkSig() { String s = "CertCheck failed, crash!!!"; String f = "frida-server"; String t="/system/xbin/su"; if (System.getProperty("x")!=null) throw new RuntimeException(s+f+t); }
    public static String pin() { return "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }
    public native int nativeStrip(byte[] b);
    public long wide() { long v = 0x123456789ABCDEFL; double d2 = 3.5; return v + (long) d2; }
}
