package de.tomcory.heimdall.dex;

import android.util.Xml;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import timber.log.Timber;

public class ManifestXMLParser {
    public static List<String> parser(String rawXml) throws XmlPullParserException, IOException {
        List<String> permissionsList= new ArrayList<>();
        XmlPullParser parser = Xml.newPullParser();
        InputStream xmlStream = new ByteArrayInputStream(rawXml.getBytes());
        try {
            parser.setInput(xmlStream, null);
            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                String name;
                switch (eventType) {
                    case XmlPullParser.START_DOCUMENT:
                        break;
                    case XmlPullParser.START_TAG:
                        name = parser.getName();
                        if (name.equalsIgnoreCase("uses-permission")) {
                            String value = parser.getAttributeValue(null, "name");
                            String permission= value.replace("android.permission.","");
                            permissionsList.add(value);
                        }
                        break;
                }
                eventType = parser.next();
            }

        } finally {
            try {
                xmlStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return permissionsList;
    }


}
