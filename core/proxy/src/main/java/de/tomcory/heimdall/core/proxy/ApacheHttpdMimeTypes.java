package de.tomcory.heimdall.core.proxy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.google.common.base.Strings;
import com.google.common.io.Resources;

public class ApacheHttpdMimeTypes {

    public static final ApacheHttpdMimeTypes defaultMimeTypes = new ApacheHttpdMimeTypes();

    private Map<String, String> ext2mimetype = new TreeMap<>();

    private ApacheHttpdMimeTypes() {
        try {
            List<String> lines = Resources.readLines(Resources.getResource("mime.types"), StandardCharsets.ISO_8859_1);
            for (String l : lines) {
                if (Strings.isNullOrEmpty(l)) {
                    continue;
                }
                if (l.startsWith("#")) {
                    continue;
                }
                String[] els = l.split("\\s");
                if (els.length < 2) {
                    continue;
                }
                String mimetype = els[0];
                for (int i = 1; i < els.length; i++) {
                    ext2mimetype.put(els[i], mimetype);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getExtension(final String src) {
        if (Strings.isNullOrEmpty(src)) {
            return "";
        }
        final int p = src.lastIndexOf(".");
        if (-1 == p) {
            return "";
        }
        final String ext = src.substring(p + 1).trim();
        if (Strings.isNullOrEmpty(ext)) {
            return "";
        }
        final int extl = ext.length();
        for (int i = 0; i < extl; i++) {
            char c = ext.charAt(i);
            if (('0' <= c) && (c <= '9')) {
                continue;
            }
            if (('A' <= c) && (c <= 'Z')) {
                continue;
            }
            if (('a' <= c) && (c <= 'z')) {
                continue;
            }
            return ext.substring(0, i);
        }
        return ext;
    }

    public String getMimeType(final String ext) {
        if (Strings.isNullOrEmpty(ext)) {
            return "";
        }
        String r = ext2mimetype.get(ext.toLowerCase());
        return Strings.isNullOrEmpty(r) ? "" : r;
    }
}
