package de.tomcory.heimdall.core.database

import androidx.room.TypeConverter
import de.tomcory.heimdall.core.database.entity.Protocol
import de.tomcory.heimdall.core.database.entity.SecurityProtocol

class HeimdallTypeConverters {
    @TypeConverter
    fun fromProtocol(protocol: Protocol): String = protocol.name

    @TypeConverter
    fun toProtocol(value: String): Protocol = Protocol.valueOf(value)

    @TypeConverter
    fun fromSecurityProtocol(securityProtocol: SecurityProtocol?): String? = securityProtocol?.name

    @TypeConverter
    fun toSecurityProtocol(value: String?): SecurityProtocol? = value?.let { SecurityProtocol.valueOf(it) }
}
