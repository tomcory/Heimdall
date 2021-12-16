package de.tomcory.heimdall.util;

public class SecondLevelDomains {
    public static String[] tlds = {"ag", "at", "bz", "cn", "co", "im", "in", "lc", "mx", "ph", "pl", "sc", "so", "uk", "vc"};
    public static String[] slds = {"com", "net", "org", "co", "nom", "or", "ind", "gen", "firm", "l", "p", "info", "biz", "me"};

    public static boolean matchesTld(String tld) {
        for(String t : tlds) {
            if(t.equals(tld)) {
                return true;
            }
        }
        return false;
    }

    public static boolean matchesSld(String sld) {
        for(String s : slds) {
            if(s.equals(sld)) {
                return true;
            }
        }
        return false;
    }
}
