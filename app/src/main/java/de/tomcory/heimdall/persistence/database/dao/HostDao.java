package de.tomcory.heimdall.persistence.database.dao;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;
import androidx.room.Transaction;
import androidx.room.Update;

import java.util.List;

import de.tomcory.heimdall.persistence.database.entity.Host;
import io.reactivex.Completable;
import io.reactivex.Flowable;
import io.reactivex.Single;

@Dao
public abstract class HostDao {

    // Queries

    @Query("SELECT * FROM Host")
    public abstract Flowable<List<Host>> getAll();

    @Query("SELECT * FROM Host")
    public abstract List<Host> getAllSync();

    @Query("SELECT * FROM Host WHERE hostname = :hostname")
    public abstract Flowable<Host> get(String hostname);

    @Query("SELECT * FROM Host WHERE hostname = :hostname")
    public abstract Host getSync(String hostname);

    // Insert

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract Single<Long> insert(Host host);

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract long insertSync(Host host);

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract Single<List<Long>> insert(List<Host> hosts);

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract List<Long> insertSync(List<Host> hosts);

    @Transaction
    public void upsertSync(Host host) {
        if(insertSync(host) == -1L) {
            updateSync(host);
        }
    }

    // Update

    @Update
    public abstract Completable update(Host host);

    @Update
    public abstract void updateSync(Host host);

    // Delete

    @Delete
    public abstract Completable delete(Host host);

    @Delete
    public abstract void deleteSync(Host host);
}
