package cn.edu.ustc.dsh.mobile;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.Bundle;
import android.content.Intent;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Test APK only. Runs in its own process without target APK or Kotlin classes. */
public final class FixtureDocumentProvider extends ContentProvider {
    public static final Uri URI = Uri.parse("content://cn.edu.ustc.dsh.mobile.test.documents/attachment");
    public static final String NAME = "APK 文件夹具.txt";
    public static final byte[] BYTES = "public Android upload fixture\n".getBytes(StandardCharsets.UTF_8);

    @Override public boolean onCreate() { return true; }
    @Override public Bundle call(String method, String arg, Bundle extras) {
        if (!"createExport".equals(method) && !"findExport".equals(method) && !"resetExports".equals(method)) return super.call(method, arg, extras);
        long identity = android.os.Binder.clearCallingIdentity();
        try {
            if ("resetExports".equals(method)) return getContext().getContentResolver().call(Uri.parse("content://cn.edu.ustc.dsh.mobile.test.exports"), "fixture.reset", null, null);
            Uri uri = "findExport".equals(method)
                ? (Uri) getContext().getContentResolver().call(Uri.parse("content://cn.edu.ustc.dsh.mobile.test.exports"), "fixture.find", arg, null).getParcelable("uri")
                : DocumentsContract.createDocument(getContext().getContentResolver(), DocumentsContract.buildDocumentUri("cn.edu.ustc.dsh.mobile.test.exports", "root"), "application/octet-stream", arg);
            getContext().grantUriPermission("cn.edu.ustc.dsh.mobile", uri, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            Bundle result = new Bundle(); result.putParcelable("uri", uri); return result;
        } catch (FileNotFoundException error) { throw new IllegalStateException("test document unavailable"); }
        finally { android.os.Binder.restoreCallingIdentity(identity); }
    }
    @Override public String getType(Uri uri) { return "text/plain"; }
    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        if (!URI.equals(uri)) throw new IllegalArgumentException();
        String[] columns = projection != null ? projection : new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE};
        MatrixCursor cursor = new MatrixCursor(columns);
        MatrixCursor.RowBuilder row = cursor.newRow();
        for (String column : columns) row.add(OpenableColumns.DISPLAY_NAME.equals(column) ? NAME : OpenableColumns.SIZE.equals(column) ? BYTES.length : null);
        return cursor;
    }
    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!URI.equals(uri) || !"r".equals(mode)) throw new FileNotFoundException();
        File file = new File(getContext().getCacheDir(), "public-upload-fixture.txt");
        try (FileOutputStream out = new FileOutputStream(file)) { out.write(BYTES); }
        catch (IOException error) { throw new FileNotFoundException("fixture unavailable"); }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { throw new UnsupportedOperationException(); }
}
