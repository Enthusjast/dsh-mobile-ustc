package cn.edu.ustc.dsh.mobile;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
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
