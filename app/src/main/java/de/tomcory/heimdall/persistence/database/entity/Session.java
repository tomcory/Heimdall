package de.tomcory.heimdall.persistence.database.entity;

import androidx.room.ColumnInfo;
import androidx.room.Embedded;
import androidx.room.Entity;
import androidx.room.PrimaryKey;
import androidx.room.Relation;

import java.util.List;

@Entity
public class Session {

    @PrimaryKey(autoGenerate = true)
    public long sessionId;
    public long timestamp;
    @ColumnInfo(defaultValue = "-1")
    public long duration;

    public Session() {
    }

    public static class SessionWithFlows {
        @Embedded
        public Session session;
        @Relation(
                parentColumn = "sessionId",
                entityColumn = "sessionId"
        )
        public List<Flow> flows;
    }
}
