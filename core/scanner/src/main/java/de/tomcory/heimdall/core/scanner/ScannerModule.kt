package de.tomcory.heimdall.core.scanner

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesDataSource

@Module
@InstallIn(SingletonComponent::class)
object ScannerModule {
    @Provides
    fun provideExodusUpdater(
        database: HeimdallDatabase
    ): ExodusUpdater {
        return ExodusUpdater(database)
    }

    @Provides
    fun provideLibraryScanner(
        database: HeimdallDatabase,
        preferences: PreferencesDataSource,
        exodusUpdater: ExodusUpdater
    ): LibraryScanner {
        return LibraryScanner(database, preferences, exodusUpdater)
    }

    @Provides
    fun providePermissionScanner(
        database: HeimdallDatabase
    ): PermissionScanner {
        return PermissionScanner(database)
    }
}