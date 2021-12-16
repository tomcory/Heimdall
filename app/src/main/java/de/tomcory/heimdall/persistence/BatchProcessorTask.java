package de.tomcory.heimdall.persistence;

import java.util.List;
import java.util.TimerTask;

import de.tomcory.heimdall.persistence.database.TrafficDatabase;
import de.tomcory.heimdall.persistence.database.entity.Flow;
import timber.log.Timber;

public class BatchProcessorTask extends TimerTask {

    @Override
    public void run() {
        List<Flow> flowSnapshot = TrafficDatabase.getInstance().getFlowUpdateCacheSnapshot();
        if(flowSnapshot != null) {
            int updated = TrafficDatabase.getInstance().getFlowDao().upsertSync(flowSnapshot);
            Timber.d("Updated " + updated + " connections");
        }
    }
}
