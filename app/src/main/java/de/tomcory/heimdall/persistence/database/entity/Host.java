package de.tomcory.heimdall.persistence.database.entity;

import androidx.annotation.NonNull;
import androidx.room.Embedded;
import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.Junction;
import androidx.room.PrimaryKey;
import androidx.room.Relation;

import java.util.List;

@Entity
public class Host {

    @NonNull
    @PrimaryKey
    public String hostname;

    public String payLevelDomain;

    @Ignore
    public Host(@NonNull String hostname) {
        this.hostname = hostname;
    }

    public Host(@NonNull String hostname, String payLevelDomain) {
        this.hostname = hostname;
        this.payLevelDomain = payLevelDomain;
    }

    public static class HostWithApps {
        @Embedded
        public Host host;
        @Relation(
                parentColumn = "hostname",
                entityColumn = "appPackage",
                associateBy = @Junction(Connection.class)
        )
        public List<App> apps;
    }
}
