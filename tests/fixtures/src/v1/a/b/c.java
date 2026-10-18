package a.b;
import com.google.ads.interactivemedia.v3.api.*;
public final class c {
    public static StreamRequest a(ImaSdkFactory f, String id, String vid) {
        return f.createVodStreamRequest(id, vid, "apikey-123");
    }
    public static int b(int x) { switch (x) { case 1: return 7; case 2: return 9; case 3: return 11; default: return 0; } }
    public void d(String url) {
        if (url.contains("/ads/") || url.contains("fwmrm.net")) { throw new IllegalStateException("ad origin " + url); }
    }
    public static String e() { return "EXT-X-DATERANGE:CLASS=\"com.apple.hls.interstitial\" SCTE35-OUT=0xFC"; }
    public static boolean isAdDisabled() { return false; }
    public static int[] arr() { return new int[]{1,2,3,4}; }
}
