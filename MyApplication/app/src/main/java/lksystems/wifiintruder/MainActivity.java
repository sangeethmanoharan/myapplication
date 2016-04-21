package lksystems.wifiintruder;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.DhcpInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.text.Html;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.SimpleAdapter;
import android.widget.TextView;
import android.widget.Toast;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdRequest.Builder;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import com.google.android.gms.ads.InterstitialAd;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import jcifs.netbios.NbtException;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Type;

public class MainActivity extends Activity {
    static DBHelper BD = null;
    static DBHelper BD2 = null;
    static DBHelper BD3 = null;
    static String DB_NAME = "bd";
    static String DB_NAME2 = "bdsettings";
    static String DB_NAME3 = "bdvendor";
    static String FirstNumberIP = BuildConfig.VERSION_NAME;
    static int IdDispositivoEscogido = 0;
    static final String KEY_COL1 = "field1";
    static final String KEY_COL2 = "field2";
    static final String KEY_ID = "_id";
    static boolean Killed;
    static String LastNumberIP = BuildConfig.VERSION_NAME;
    static String LinkSpeed = BuildConfig.VERSION_NAME;
    static String MyDHCPServ = BuildConfig.VERSION_NAME;
    static String MyDNS1 = BuildConfig.VERSION_NAME;
    static String MyDNS2 = BuildConfig.VERSION_NAME;
    static String MyGateWay = BuildConfig.VERSION_NAME;
    static String MyIP = BuildConfig.VERSION_NAME;
    static String MyMac = BuildConfig.VERSION_NAME;
    static String MyMasc = BuildConfig.VERSION_NAME;
    static String MySSID = BuildConfig.VERSION_NAME;
    static String MyVendor = BuildConfig.VERSION_NAME;
    static boolean NeedScan = false;
    static int NumberOnList = 0;
    static String PartialIP = BuildConfig.VERSION_NAME;
    static boolean PrimeraVezFirstScreen;
    static String SecondNumberIP = BuildConfig.VERSION_NAME;
    static String ThirdNumberIP = BuildConfig.VERSION_NAME;
    static int ToastHelper = 0;
    static int VersionApp = 0;
    static int VersionDB = 0;
    static InterstitialAd interstitial;
    static InterstitialAd interstitial2;
    static SQLiteDatabase myDataBase;
    static SQLiteDatabase myDataBase2;
    int BotonBack = 0;
    List<ScanResult> Intensidad;
    ListView Lista;
    Context MyContext = this;
    TextView Temp1;
    TextView Temp2;
    TextView Temp3;
    TextView Temp4;
    TextView Temp5;
    TextView Temp6;
    int TempIntensidad = 0;
    SimpleAdapter adapter;
    ArrayList<HashMap<String, String>> list = new ArrayList();
    int size = 0;
    Timer timer = new Timer();
    Toast toast;
    WifiManager wifi;

    public class DBHelper extends SQLiteOpenHelper {
        final Context myContext;

        public DBHelper(Context context) {
            super(MainActivity.this.MyContext, MainActivity.DB_NAME, null, 1);
            this.myContext = context;
        }

        public boolean removeSettings() {
            return MainActivity.myDataBase.delete("settings", null, null) > 0;
        }

        public long insertSettings(String Version, int Votar) {
            ContentValues newValues = new ContentValues();
            newValues.put("version", Version);
            newValues.put("votar", Integer.valueOf(Votar));
            return MainActivity.myDataBase.insert("settings", null, newValues);
        }

        public long insertDispositivo(String mac, String Name) {
            ContentValues newValues = new ContentValues();
            newValues.put("mac", mac);
            newValues.put("name", Name);
            return MainActivity.myDataBase.insert("friend_list", null, newValues);
        }

        public boolean removeDispositivo(String mac) {
            if (mac.equals("todo")) {
                if (MainActivity.myDataBase.delete("friend_list", null, null) > 0) {
                    return true;
                }
                return false;
            } else if (MainActivity.myDataBase.delete("friend_list", "mac='" + mac.toString() + "'", null) <= 0) {
                return false;
            } else {
                return true;
            }
        }

        public boolean updateAlarma(Integer _rowIndex, String categoria, String nombreplato) {
            ContentValues newValues = new ContentValues();
            newValues.put(MainActivity.KEY_COL1, categoria);
            newValues.put(MainActivity.KEY_COL2, nombreplato);
            return MainActivity.myDataBase.update("alarma", newValues, new StringBuilder().append("_id=").append(_rowIndex).toString(), null) > 0;
        }

        public boolean updateCat(Integer _rowIndex, String categoria) {
            ContentValues newValues = new ContentValues();
            newValues.put(MainActivity.KEY_COL1, categoria);
            return MainActivity.myDataBase.update("alarma", newValues, new StringBuilder().append("_id=").append(_rowIndex).toString(), null) > 0;
        }

        public void createDataBase() throws IOException {
            if (!checkDataBase()) {
                getReadableDatabase();
                try {
                    copyDataBase();
                } catch (IOException e) {
                    throw new Error("Error copiando Base de Datos");
                }
            }
        }

        public boolean checkDataBase() {
            SQLiteDatabase checkDB = null;
            try {
                checkDB = SQLiteDatabase.openDatabase(MainActivity.this.getFilesDir().getPath() + MainActivity.DB_NAME, null, 0);
            } catch (SQLiteException e) {
            }
            if (checkDB != null) {
                checkDB.close();
            }
            if (checkDB != null) {
                return true;
            }
            return false;
        }

        public void copyDataBase() throws IOException {
            String Temp = this.myContext.getAssets().toString();
            InputStream myInput = this.myContext.getAssets().open(MainActivity.DB_NAME);
            OutputStream myOutput = new FileOutputStream(MainActivity.this.getFilesDir().getPath() + MainActivity.DB_NAME);
            byte[] buffer = new byte[Flags.FLAG5];
            while (true) {
                int length = myInput.read(buffer);
                if (length > 0) {
                    myOutput.write(buffer, 0, length);
                } else {
                    myOutput.flush();
                    myOutput.close();
                    myInput.close();
                    return;
                }
            }
        }

        public void open() throws SQLException {
            try {
                createDataBase();
                String myPath = MainActivity.this.getFilesDir().getPath() + MainActivity.DB_NAME;
                if (MainActivity.DB_NAME == "bdvendor") {
                    MainActivity.myDataBase2 = SQLiteDatabase.openDatabase(myPath, null, 0);
                    try {
                        MainActivity.myDataBase.execSQL("delete from vendor");
                        return;
                    } catch (SQLiteException e) {
                        return;
                    }
                }
                MainActivity.myDataBase = SQLiteDatabase.openDatabase(myPath, null, 0);
            } catch (IOException e2) {
                throw new Error("Ha sido imposible crear la Base de Datos");
            }
        }

        public synchronized void close() {
            if (MainActivity.DB_NAME == "bdvendor") {
                if (MainActivity.myDataBase2 != null) {
                    MainActivity.myDataBase2.close();
                }
            } else if (MainActivity.myDataBase != null) {
                MainActivity.myDataBase.close();
            }
            super.close();
        }

        public void onCreate(SQLiteDatabase db) {
        }

        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            Toast.makeText(MainActivity.this.MyContext, "entra en update", 0).show();
        }
    }

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        interstitial = new InterstitialAd(this);
        interstitial2 = new InterstitialAd(this);
        interstitial.setAdUnitId("ca-app-pub-2885006023541960/3057467337");
        interstitial2.setAdUnitId("ca-app-pub-2885006023541960/6333472135");
        AdRequest adRequest2 = new Builder().build();
        if (FirstScreen.TempPubli) {
            interstitial2.loadAd(adRequest2);
        }
        interstitial2.setAdListener(new AdListener() {
            public void onAdClosed() {
                MainActivity.this.wifi = (WifiManager) MainActivity.this.getSystemService("wifi");
                WifiInfo wifiInfo = MainActivity.this.wifi.getConnectionInfo();
                if (!MainActivity.this.wifi.isWifiEnabled() || MainActivity.MyIP.equals("0.0.0.0")) {
                    Toast.makeText(MainActivity.this.MyContext, MainActivity.this.getResources().getString(R.string.RedNoLista), 0).show();
                    MainActivity.this.wifi.setWifiEnabled(true);
                    return;
                }
                MainActivity.this.timer.cancel();
                MainActivity.NeedScan = true;
                Intent intent = new Intent(MainActivity.this.MyContext, Red.class);
                intent.addFlags(SmbConstants.READ_CONTROL);
                MainActivity.this.startActivity(intent);
            }
        });
        interstitial.setAdListener(new AdListener() {
            public void onAdClosed() {
                MainActivity.this.timer.cancel();
                Intent intent = new Intent(MainActivity.this.MyContext, Exit.class);
                intent.addFlags(SmbConstants.READ_CONTROL);
                MainActivity.this.startActivity(intent);
                MainActivity.this.finish();
            }
        });
        Killed = true;
        DB_NAME = DB_NAME2;
        BD2 = new DBHelper(this.MyContext);
        if (PrimeraVezFirstScreen) {
            setContentView(R.layout.activity_main);
            this.Temp1 = (TextView) findViewById(R.id.textViewTitulo1);
            this.Temp2 = (TextView) findViewById(R.id.textViewTitulo2);
            this.Temp3 = (TextView) findViewById(R.id.textViewRed);
            this.Temp5 = (TextView) findViewById(R.id.textViewRed2);
            this.Temp1.setText(getResources().getString(R.string.Titulo1));
            this.Temp2.setText(getResources().getString(R.string.Titulo2));
            this.Temp3.setText(getResources().getString(R.string.ConectadoRed) + " ");
            DB_NAME = "bd";
            BD = new DBHelper(this.MyContext);
            BD.open();
            DB_NAME = "bdvendor";
            BD3 = new DBHelper(this.MyContext);
            BD3.open();
            this.wifi = (WifiManager) getSystemService("wifi");
            if (!this.wifi.isWifiEnabled()) {
                Toast.makeText(getApplicationContext(), getResources().getString(R.string.ActivandoWifi), 1).show();
                this.wifi.setWifiEnabled(true);
            }
            this.list.clear();
            this.Lista = (ListView) findViewById(R.id.List);
            this.Lista.setDividerHeight(0);
            this.Lista.setDivider(null);
            this.adapter = new SimpleAdapter(this.MyContext, this.list, R.layout.main_item_two_line_rows_main, new String[]{"line1", "line2"}, new int[]{R.id.text1, R.id.text2});
            this.Lista.setAdapter(this.adapter);
            this.Lista.setSelector(17170445);
            this.Lista.setCacheColorHint(0);
            return;
        }
        Intent intent = new Intent(getApplicationContext(), FirstScreen.class);
        intent.addFlags(SmbConstants.READ_CONTROL);
        startActivity(intent);
        finish();
    }

    public void MostrarBienvenida() {
        OnClickListener dialogClickListener = new OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                }
            }
        };
        CharSequence styledText = Html.fromHtml(String.format(getResources().getString(R.string.TituloBienvenida), new Object[0]));
        CharSequence styledText2 = Html.fromHtml(String.format(getResources().getString(R.string.TextoBienvenida), new Object[0]));
        AlertDialog.Builder builder = new AlertDialog.Builder(this.MyContext);
        builder.setPositiveButton(getResources().getString(R.string.Yes), dialogClickListener).setTitle(styledText).setIcon(R.drawable.icononotificacion).setPositiveButton("OK", dialogClickListener).setCancelable(false).setMessage(styledText2);
        builder.show();
    }

    protected void onResume() {
        WifiInfo wifiInfo2 = this.wifi.getConnectionInfo();
        String MacTemporal = wifiInfo2.getMacAddress();
        MyMac = MacTemporal;
        try {
            MacTemporal = MacTemporal.substring(0, MacTemporal.length() - 9);
        } catch (Exception e) {
            Intent intent = new Intent(getApplicationContext(), FirstScreen.class);
            intent.addFlags(SmbConstants.READ_CONTROL);
            startActivity(intent);
            finish();
        }
        String Temp = BuildConfig.VERSION_NAME;
        Cursor cursor = myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.toUpperCase() + "'", null);
        if (cursor.moveToFirst()) {
            for (int i = 1; cursor.getCount() >= i; i++) {
                MyVendor = cursor.getString(0);
                cursor.moveToNext();
            }
        }
        cursor.close();
        MySSID = wifiInfo2.getSSID();
        if (MySSID != null) {
            this.Temp5.setText(" " + MySSID);
        } else {
            MySSID = getResources().getString(R.string.SinConexion);
        }
        this.timer.cancel();
        this.timer = new Timer();
        this.timer.scheduleAtFixedRate(new TimerTask() {
            public void run() {
                MainActivity.this.ActualizaLista();
            }
        }, 0, 1000);
        AdView adView = new AdView(this);
        adView.setAdUnitId("ca-app-pub-2885006023541960/6784204136");
        adView.setAdSize(AdSize.SMART_BANNER);
        adView = (AdView) findViewById(R.id.adView);
        adView.loadAd(new Builder().build());
        final AdView finalAdView = adView;
        adView.setAdListener(new AdListener() {
            public void onAdLoaded() {
                int height = finalAdView.getHeight();
                RelativeLayout relativeLayout = new RelativeLayout(MainActivity.this.MyContext);
                ((RelativeLayout) MainActivity.this.findViewById(R.id.Todo2)).setPadding(0, 0, 0, height + 1);
            }
        });
        super.onResume();
    }

    public void ActualizaLista() {
        boolean Temp = false;
        WifiInfo wifiInfo = this.wifi.getConnectionInfo();
        int ip = wifiInfo.getIpAddress();
        if (!MyIP.equals(String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 24) & Type.ANY)}))) {
            Temp = true;
            MyIP = String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 24) & Type.ANY)});
        }
        PartialIP = String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)}) + ".";
        FirstNumberIP = String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)});
        SecondNumberIP = String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)});
        ThirdNumberIP = String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)});
        LastNumberIP = String.format("%d", new Object[]{Integer.valueOf((ip >> 24) & Type.ANY)});
        DhcpInfo d = this.wifi.getDhcpInfo();
        StringBuilder append = new StringBuilder().append(d.gateway & Type.ANY).append(".");
        int i = d.gateway >>> 8;
        d.gateway = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.gateway >>> 8;
        d.gateway = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.gateway >>> 8;
        d.gateway = i;
        MyGateWay = append.append(i & Type.ANY).toString();
        append = new StringBuilder().append(d.netmask & Type.ANY).append(".");
        i = d.netmask >>> 8;
        d.netmask = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.netmask >>> 8;
        d.netmask = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.netmask >>> 8;
        d.netmask = i;
        MyMasc = append.append(i & Type.ANY).toString();
        append = new StringBuilder().append(d.serverAddress & Type.ANY).append(".");
        i = d.serverAddress >>> 8;
        d.serverAddress = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.serverAddress >>> 8;
        d.serverAddress = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.serverAddress >>> 8;
        d.serverAddress = i;
        MyDHCPServ = append.append(i & Type.ANY).toString();
        append = new StringBuilder().append(d.dns1 & Type.ANY).append(".");
        i = d.dns1 >>> 8;
        d.dns1 = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.dns1 >>> 8;
        d.dns1 = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.dns1 >>> 8;
        d.dns1 = i;
        MyDNS1 = append.append(i & Type.ANY).toString();
        append = new StringBuilder().append(d.dns2 & Type.ANY).append(".");
        i = d.dns2 >>> 8;
        d.dns2 = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.dns2 >>> 8;
        d.dns2 = i;
        append = append.append(i & Type.ANY).append(".");
        i = d.dns2 >>> 8;
        d.dns2 = i;
        MyDNS2 = append.append(i & Type.ANY).toString();
        if (!LinkSpeed.equals(String.valueOf(wifiInfo.getLinkSpeed()))) {
            Temp = true;
            LinkSpeed = String.valueOf(wifiInfo.getLinkSpeed());
        }
        HashMap<String, String> item = new HashMap();
        if (Temp) {
            this.list.clear();
            MySSID = wifiInfo.getSSID();
            if (MyIP.equals("0.0.0.0")) {
                item = new HashMap();
                item.put("line1", getResources().getString(R.string.NoConection) + " ");
                item.put("line2", getResources().getString(R.string.NoConection2));
                this.list.add(item);
            } else {
                item = new HashMap();
                item.put("line1", "IP: ");
                item.put("line2", MyIP);
                this.list.add(item);
                item = new HashMap();
                item.put("line1", getResources().getString(R.string.MACAdress) + " ");
                item.put("line2", MyMac);
                this.list.add(item);
                item = new HashMap();
                item.put("line1", getResources().getString(R.string.GateWay) + " ");
                item.put("line2", MyGateWay);
                this.list.add(item);
                item = new HashMap();
                item = new HashMap();
                item.put("line1", getResources().getString(R.string.MascRed) + " \n");
                item.put("line2", MyMasc + "\n");
                this.list.add(item);
                item = new HashMap();
                item.put("line1", getResources().getString(R.string.VelocidadConexion) + " \n");
                item.put("line2", LinkSpeed + " Mbps\n");
                this.list.add(item);
                item = new HashMap();
                item.put("line1", getResources().getString(R.string.DHCP) + " \n");
                item.put("line2", MyDHCPServ + "\n");
                this.list.add(item);
                item = new HashMap();
                item.put("line1", "DNS: ");
                item.put("line2", MyDNS1 + "\n" + MyDNS2);
                this.list.add(item);
            }
            runOnUiThread(new Runnable() {
                public void run() {
                    MainActivity.this.adapter.notifyDataSetChanged();
                }
            });
        }
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.action_borrar /*2131099714*/:
                OnClickListener dialogClickListener = new OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        switch (which) {
                            case NbtException.CONNECTION_REFUSED /*-1*/:
                                MainActivity.BD.removeDispositivo("todo");
                                MainActivity.this.onResume();
                                return;
                            default:
                                return;
                        }
                    }
                };
                AlertDialog.Builder builder = new AlertDialog.Builder(this.MyContext);
                builder.setPositiveButton(getResources().getString(R.string.Yes), dialogClickListener).setTitle(getResources().getString(R.string.TituloBorrar)).setIcon(17301642).setNegativeButton(getResources().getString(R.string.Cancelar), dialogClickListener).setCancelable(false).setCancelable(false).setMessage(getResources().getString(R.string.TextoBorrarLista));
                builder.show();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    public void OnClickStart(View v) {
        if (interstitial2.isLoaded()) {
            interstitial2.show();
        } else {
            new Thread() {
                public void run() {
                    try {
                        if (!isInterrupted()) {
                            Thread.sleep(1500);
                            MainActivity.this.runOnUiThread(new Runnable() {
                                public void run() {
                                    MainActivity.this.Empezar();
                                }
                            });
                            throw new InterruptedException();
                        }
                    } catch (InterruptedException e) {
                    }
                }
            }.start();
        }
    }

    public void Empezar() {
        if (interstitial2.isLoaded()) {
            interstitial2.show();
            return;
        }
        this.wifi = (WifiManager) getSystemService("wifi");
        if (!this.wifi.isWifiEnabled() || MyIP.equals("0.0.0.0")) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.RedNoLista), 0).show();
            this.wifi.setWifiEnabled(true);
            return;
        }
        this.timer.cancel();
        NeedScan = true;
        Intent intent = new Intent(this.MyContext, Red.class);
        intent.addFlags(SmbConstants.READ_CONTROL);
        startActivity(intent);
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (VERSION.SDK_INT < 5 && keyCode == 4 && event.getRepeatCount() == 0) {
            onBackPressed();
        }
        return super.onKeyDown(keyCode, event);
    }

    public void onBackPressed() {
        if (interstitial.isLoaded()) {
            interstitial.show();
            return;
        }
        this.timer.cancel();
        Intent intent = new Intent(this.MyContext, Exit.class);
        intent.addFlags(SmbConstants.GENERIC_EXECUTE);
        startActivity(intent);
        finish();
    }

    protected void onPause() {
        this.timer.cancel();
        super.onPause();
    }

    protected void onStop() {
        this.timer.cancel();
        super.onStop();
    }

    protected void onRestart() {
        super.onRestart();
    }

    protected void onDestroy() {
        this.timer.cancel();
        super.onDestroy();
    }
}
