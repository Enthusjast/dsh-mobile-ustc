package cn.edu.ustc.dsh.mobile;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.CancellationSignal;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.UUID;

/** Real test APK DocumentsProvider, independent of the target APK's Kotlin runtime. */
public final class FixtureExportProvider extends DocumentsProvider {
    private final java.util.concurrent.ConcurrentHashMap<String, String> names = new java.util.concurrent.ConcurrentHashMap<>();
    @Override public boolean onCreate() { return true; }
    @Override public Bundle call(String method, String arg, Bundle extras) {
        if ("fixture.find".equals(method)) {
            for (java.util.Map.Entry<String, String> entry : names.entrySet()) if (entry.getValue().equals(arg)) {
                Bundle result = new Bundle(); result.putParcelable("uri", android.provider.DocumentsContract.buildDocumentUri("cn.edu.ustc.dsh.mobile.test.exports", entry.getKey())); return result;
            }
            throw new IllegalArgumentException();
        }
        if (!"fixture.reset".equals(method)) return super.call(method, arg, extras);
        File[] files = getContext().getCacheDir().listFiles();
        if (files != null) for (File target : files) if (target.getName().startsWith("export-")) target.delete();
        return new Bundle();
    }
    private File file(String id) throws FileNotFoundException {
        if (!id.matches("[a-z-]+[0-9a-f-]{36}")) throw new FileNotFoundException();
        return new File(getContext().getCacheDir(), "export-" + id);
    }
    @Override public Cursor queryRoots(String[] projection) {
        String[] columns = projection != null ? projection : new String[]{Root.COLUMN_ROOT_ID, Root.COLUMN_DOCUMENT_ID, Root.COLUMN_TITLE, Root.COLUMN_FLAGS};
        MatrixCursor cursor = new MatrixCursor(columns); MatrixCursor.RowBuilder row = cursor.newRow();
        for (String column : columns) row.add(Root.COLUMN_ROOT_ID.equals(column) || Root.COLUMN_DOCUMENT_ID.equals(column) ? "root" : Root.COLUMN_TITLE.equals(column) ? "Export fixture" : Root.COLUMN_FLAGS.equals(column) ? Root.FLAG_SUPPORTS_CREATE : null);
        return cursor;
    }
    @Override public String createDocument(String parent, String mime, String name) throws FileNotFoundException {
        String id = name + "-" + UUID.randomUUID();
        try { if (!file(id).createNewFile()) throw new IOException(); } catch (IOException error) { throw new FileNotFoundException(); }
        names.put(id, name); return id;
    }
    @Override public Cursor queryDocument(String id, String[] projection) throws FileNotFoundException {
        boolean root = "root".equals(id);
        if (!root && !file(id).exists()) throw new FileNotFoundException();
        String[] columns = projection != null ? projection : new String[]{Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE, Document.COLUMN_FLAGS, Document.COLUMN_SIZE};
        MatrixCursor cursor = new MatrixCursor(columns); MatrixCursor.RowBuilder row = cursor.newRow();
        int flags = root ? Document.FLAG_DIR_SUPPORTS_CREATE : Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_RENAME | (id.startsWith("unsupported-") ? 0 : Document.FLAG_SUPPORTS_DELETE);
        for (String column : columns) row.add(Document.COLUMN_DOCUMENT_ID.equals(column) ? id : Document.COLUMN_DISPLAY_NAME.equals(column) ? names.getOrDefault(id, id) : Document.COLUMN_MIME_TYPE.equals(column) ? root ? Document.MIME_TYPE_DIR : "application/octet-stream" : Document.COLUMN_FLAGS.equals(column) ? flags : Document.COLUMN_SIZE.equals(column) ? root ? 0L : file(id).length() : null);
        return cursor;
    }
    @Override public Cursor queryChildDocuments(String parent, String[] projection, String sort) { return new MatrixCursor(projection != null ? projection : new String[]{Document.COLUMN_DOCUMENT_ID}); }
    @Override public ParcelFileDescriptor openDocument(String id, String mode, CancellationSignal signal) throws FileNotFoundException {
        File target = file(id);
        if (id.startsWith("cleanup-failure-") && "rwt".equals(mode)) throw new FileNotFoundException();
        if (id.startsWith("corrupt-") && "r".equals(mode)) {
            try (FileOutputStream output = new FileOutputStream(target, true)) { output.write(1); } catch (IOException error) { throw new FileNotFoundException(); }
        }
        return ParcelFileDescriptor.open(target, ParcelFileDescriptor.parseMode(mode));
    }
    @Override public String renameDocument(String id, String name) throws FileNotFoundException {
        if (!file(id).exists()) throw new FileNotFoundException();
        if (id.startsWith("moving-")) {
            String next = "moving-" + UUID.randomUUID();
            if (!file(id).renameTo(file(next))) throw new FileNotFoundException();
            names.remove(id); names.put(next, name); return next;
        }
        names.put(id, name); return null; // Stable document ID: preserve the existing URI grant.
    }
    @Override public void deleteDocument(String id) throws FileNotFoundException {
        if (id.startsWith("cleanup-failure-") || !file(id).delete()) throw new FileNotFoundException();
        names.remove(id);
    }
}
