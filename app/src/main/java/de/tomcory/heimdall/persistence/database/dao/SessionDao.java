package de.tomcory.heimdall.persistence.database.dao;

import androidx.room.Dao;
import androidx.room.Delete;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;
import androidx.room.Transaction;
import androidx.room.Update;

import java.util.List;

import de.tomcory.heimdall.persistence.database.entity.Session;
import io.reactivex.Completable;
import io.reactivex.Flowable;
import io.reactivex.Single;

@Dao
public abstract class SessionDao {

    // Queries

    @Query("SELECT * FROM Session")
    public abstract Flowable<List<Session>> getAll();

    @Query("SELECT * FROM Session")
    public abstract List<Session> getAllSync();

    @Query("SELECT * FROM Session WHERE sessionId = :sessionId")
    public abstract Flowable<Session> get(long sessionId);

    @Query("SELECT * FROM Session WHERE sessionId = :sessionId")
    public abstract Session getSync(long sessionId);

    // Insert

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract Single<Long> insert(Session session);

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract long insertSync(Session session);

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract Single<List<Long>> insert(List<Session> sessions);

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    public abstract List<Long> insertSync(List<Session> sessions);

    @Transaction
    public void upsertSync(Session session) {
        if(insertSync(session) == -1L) {
            updateSync(session);
        }
    }

    // Update

    @Update
    public abstract Completable update(Session session);

    @Update
    public abstract void updateSync(Session session);

    // Delete

    @Delete
    public abstract Completable delete(Session session);

    @Delete
    public abstract void deleteSync(Session session);
}
