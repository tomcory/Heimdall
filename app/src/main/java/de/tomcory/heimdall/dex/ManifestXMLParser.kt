package de.tomcory.heimdall.dex

import android.util.Xml
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserException
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

object ManifestXMLParser {
    @Deprecated("Use core.scanner implementation instead.")
    @Throws(XmlPullParserException::class, IOException::class)
    fun parser(rawXml: String): List<String> {
        val permissionsList: MutableList<String> = ArrayList()
        val parser = Xml.newPullParser()
        val xmlStream: InputStream = ByteArrayInputStream(rawXml.toByteArray())
        try {
            parser.setInput(xmlStream, null)
            var eventType = parser.eventType
            while (eventType != XmlPullParser.END_DOCUMENT) {
                var name: String
                when (eventType) {
                    XmlPullParser.START_DOCUMENT -> {}
                    XmlPullParser.START_TAG -> {
                        name = parser.name
                        if (name.equals("uses-permission", ignoreCase = true)) {
                            val value = parser.getAttributeValue(null, "name")
                            val permission = value.replace("android.permission.", "")
                            permissionsList.add(value)
                        }
                    }
                }
                eventType = parser.next()
            }
        } finally {
            try {
                xmlStream.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
        return permissionsList
    }
}