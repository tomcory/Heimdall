package de.tomcory.heimdall.persistence.database.entity;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.PrimaryKey;

@Entity
public class Flow {

    @PrimaryKey(autoGenerate = true)
    public long flowId;

    // foreign keys
    public long sessionId;
    public String appPackage;
    public String hostname;

    public long timestamp;
    @ColumnInfo(defaultValue = "-1")
    public long duration;
    public int ipVersion;
    public String protocol;
    public int port;
    public boolean isActive;
    public boolean isTls;

    public long totalBytesIn;
    public long totalBytesOut;
    public long payloadBytesIn;
    public long payloadBytesOut;
    public long packetsIn;
    public long packetsOut;

    public Flow() {
    }

    @Ignore
    public Flow(long sessionId, long timestamp, int ipVersion, String protocol, int port, boolean isActive, boolean isTls) {
        this.sessionId = sessionId;
        this.timestamp = timestamp;
        this.ipVersion = ipVersion;
        this.protocol = protocol;
        this.port = port;
        this.isActive = isActive;
        this.isTls = isTls;
    }
}
