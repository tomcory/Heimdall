package de.tomcory.heimdall.persistence.database.entity;

import android.graphics.drawable.Drawable;

import androidx.annotation.NonNull;
import androidx.room.Embedded;
import androidx.room.Entity;
import androidx.room.Ignore;
import androidx.room.Junction;
import androidx.room.PrimaryKey;
import androidx.room.Relation;

import java.util.List;
import java.util.Objects;

@Entity
public class App {

    @NonNull
    @PrimaryKey
    public String appPackage;
    public String appLabel;
    public String storeLabel;
    public String category;
    public String developerId;
    public String developerName;
    public String logoUrl;
    public long installCount;
    public boolean isFree;

    @Ignore
    public App(@NonNull String appPackage) {
        this.appPackage = appPackage;
    }

    public App(@NonNull String appPackage, String appLabel, String storeLabel, String category, String developerId, String developerName, String logoUrl, long installCount, boolean isFree) {
        this.appPackage = appPackage;
        this.appLabel = appLabel;
        this.storeLabel = storeLabel;
        this.category = category;
        this.developerId = developerId;
        this.developerName = developerName;
        this.logoUrl = logoUrl;
        this.installCount = installCount;
        this.isFree = isFree;
    }

    public static class AppWithHosts {
        @Embedded
        public App app;
        @Relation(
                parentColumn = "appPackage",
                entityColumn = "hostname",
                associateBy = @Junction(Connection.class)
        )
        public List<Host> hosts;
    }

    public static class AppGrouped {
        public String appPackage;
        public String appLabel;
        public String logoUrl;
        public long value;
        public double percentage;
        public String unit;
        @Ignore public Drawable icon;
        @Ignore public int type = 1;

        public AppGrouped(String appPackage, String appLabel, String logoUrl, long value) {
            this.appPackage = appPackage;
            this.appLabel = appLabel;
            this.logoUrl = logoUrl;
            this.value = value;
        }

        public AppGrouped(String appPackage, String appLabel, String logoUrl, long value, int type) {
            this.appPackage = appPackage;
            this.appLabel = appLabel;
            this.logoUrl = logoUrl;
            this.value = value;
            this.type = type;
        }

        @Override
        public boolean equals(Object o) {
            if(this == o) return true;
            if(o == null || getClass() != o.getClass()) return false;
            AppGrouped that = (AppGrouped) o;
            return value == that.value &&
                    Double.compare(that.percentage, percentage) == 0 &&
                    appPackage.equals(that.appPackage) &&
                    Objects.equals(appLabel, that.appLabel) &&
                    Objects.equals(logoUrl, that.logoUrl) &&
                    Objects.equals(icon, that.icon);
        }

        @Override
        public int hashCode() {
            return Objects.hash(appPackage, appLabel, logoUrl, value, icon, percentage);
        }
    }
}
