package de.tomcory.heimdall.core.database

import androidx.room.TypeConverter
import de.tomcory.heimdall.core.database.entity.Protocol

class HeimdallTypeConverters {
    @TypeConverter
    fun fromProtocol(protocol: Protocol): String = protocol.name

    @TypeConverter
    fun toProtocol(value: String): Protocol = Protocol.valueOf(value)
}
