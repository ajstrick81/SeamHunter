package com.example.tvapp.player;
import java.util.*;
import com.google.ads.interactivemedia.v3.api.*;
public class AdBreakScheduler {
    private final List<Long> cuePoints = new ArrayList<>();
    private AdsManager manager;
    public boolean shouldPlayAd(String contentId) { return contentId != null && !contentId.isEmpty(); }
    public List<Long> getAdBreaks() { return cuePoints; }
    public void onAdsManagerLoaded(AdsManagerLoadedEvent e) {
        manager = e.getAdsManager();
        for (Float f : manager.getAdCuePoints()) cuePoints.add((long)(f * 1000));
        manager.start();
    }
    public void onAdEvent(AdEvent ev) { System.out.println("AdEvent " + ev.getType()); }
    public static long[] cueTimes(List<Float> in) { long[] r = new long[in.size()]; for (int i=0;i<r.length;i++) r[i]=(long)(float)in.get(i); return r; }
    public String vastUrl() { return "https://pubads.g.doubleclick.net/gampad/ads?iu=/123/tv&output=vast&vpmute=0"; }
    public void showPauseAd() { System.out.println("pauseAd shown"); }
}
