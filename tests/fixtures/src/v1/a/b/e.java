package a.b;
import com.google.ads.interactivemedia.v3.api.*;
public final class e implements AdEvent.AdEventListener, AdErrorEvent.AdErrorListener {
    public void onAdEvent(AdEvent x) { if (x.getType() == AdEvent.AdEventType.STARTED) System.out.println("s"); }
    public void onAdError(AdErrorEvent x) { System.out.println("fallback to content"); }
}
