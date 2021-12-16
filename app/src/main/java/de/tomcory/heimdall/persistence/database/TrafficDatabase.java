package de.tomcory.heimdall.persistence.database;

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import de.tomcory.heimdall.persistence.database.dao.AppDao;
import de.tomcory.heimdall.persistence.database.dao.ConnectionDao;
import de.tomcory.heimdall.persistence.database.dao.FlowDao;
import de.tomcory.heimdall.persistence.database.dao.HostDao;
import de.tomcory.heimdall.persistence.database.dao.SessionDao;
import de.tomcory.heimdall.persistence.database.entity.App;
import de.tomcory.heimdall.persistence.database.entity.Connection;
import de.tomcory.heimdall.persistence.database.entity.Flow;
import de.tomcory.heimdall.persistence.database.entity.Host;
import de.tomcory.heimdall.persistence.database.entity.Session;

@Database(version = 1, entities = {App.class, Connection.class, Flow.class, Host.class, Session.class}, exportSchema = false)
public abstract class TrafficDatabase extends RoomDatabase {

    abstract public AppDao getAppDao();
    abstract public ConnectionDao getConnectionDao();
    abstract public FlowDao getFlowDao();
    abstract public HostDao getHostDao();
    abstract public SessionDao getSessionDao();

    private final static Object flowUpdateCacheMonitor = new Object();
    private HashMap<Long, Flow> flowUpdateCache = new HashMap<>();

    // singleton
    private static TrafficDatabase instance;

    public static boolean init(Context context) {
        if(instance == null) {
            instance = Room.databaseBuilder(context, TrafficDatabase.class, "heimdall").fallbackToDestructiveMigration().build();
            return true;
        } else {
            return false;
        }
    }

    public static TrafficDatabase getInstance() {
        return instance;
    }

    public void addFlowToUpdateCache(Flow flow) {
        synchronized (flowUpdateCacheMonitor) {
            flowUpdateCache.putIfAbsent(flow.flowId, flow);
        }
    }

    public List<Flow> getFlowUpdateCacheSnapshot() {
        synchronized (flowUpdateCacheMonitor) {
            if(flowUpdateCache.size() > 0) {
                List<Flow> snapshot = new ArrayList<>(flowUpdateCache.values());
                flowUpdateCache = new HashMap<>();
                return snapshot;
            } else {
                return null;
            }
        }
    }
}