package de.tomcory.heimdall.persistence.database.entity;

import androidx.annotation.NonNull;
import androidx.room.Entity;
import androidx.room.Index;

@Entity(primaryKeys = {"appPackage", "hostname"}, indices = {@Index(value = "appPackage"), @Index(value = "hostname")})

public class Connection {

    @NonNull
    public String appPackage;
    @NonNull
    public String hostname;

    public Connection(@NonNull String appPackage, @NonNull String hostname) {
        this.appPackage = appPackage;
        this.hostname = hostname;
    }
}
