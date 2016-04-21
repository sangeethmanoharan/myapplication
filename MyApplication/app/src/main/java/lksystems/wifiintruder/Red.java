package lksystems.wifiintruder;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.StrictMode;
import android.os.StrictMode.ThreadPolicy;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.SimpleAdapter;
import android.widget.TextView;
import android.widget.Toast;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest.Builder;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import jcifs.netbios.NbtAddress;
import jcifs.netbios.NbtException;
import org.xbill.DNS.KEYRecord.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class Red extends Activity {
    static int ContadorDeIPs = 0;
    static int ContadorDeIPs2 = 0;
    static int ContadorDispositivosEncontrados;
    static HacerPing3[] IP3 = new HacerPing3[Type.ANY];
    static int IPActual = 1;
    static String IPTemp;
    static ImageView ImagenAviso;
    static Dispositivos[] InDispositivos = new Dispositivos[1];
    static ListView Lista;
    static boolean PingFuncionando;
    static boolean ScanEnCurso = false;
    static long StartRefresh;
    static TextView Temp13;
    static String TempTextoTextView;
    static TextView TextoIntrusos;
    static SimpleAdapter adapter;
    public static Context baseContext;
    static ConnectivityManager connManager;
    static ExecutorService executor3;
    static ArrayList<HashMap<String, String>> list = new ArrayList();
    static NetworkInfo mWifi;
    static WifiManager wifi;
    HacerPing[] IP = new HacerPing[Type.ANY];
    HacerPing2[] IP2 = new HacerPing2[Type.ANY];
    Context MyContext = this;
    boolean PubliTemp = false;
    TextView Temp1;
    TextView Temp2;
    TextView Temp3;
    TextView Temp4;
    TextView Temp5;
    int TempContPreparandoRed = 0;
    long TiempoAlEmpezar;
    boolean WifiDesconectada = false;
    ExecutorService executor;
    ExecutorService executor2;
    ProgressBar myProgressBar;
    ProgressBar myProgressBar2;
    private Runnable myThread = new Runnable() {
        Handler myHandle = new Handler() {
            public void handleMessage(Message msg) {
                Red.this.myProgressBar.setProgress(Red.ContadorDeIPs2 + Red.this.TempContPreparandoRed);
            }
        };

        public void run() {
            Red.ContadorDeIPs2 = 0;
            while (Red.ContadorDeIPs2 < Type.TSIG) {
                try {
                    this.myHandle.sendMessage(this.myHandle.obtainMessage());
                    Thread.sleep(100);
                } catch (Throwable th) {
                }
            }
        }
    };

    public class Dispositivo {
        String IP = null;
        String Mac = null;
        String Name = null;
        String Vendor = null;
    }

    public class Dispositivos {
        Dispositivo[] InDispositivo = new Dispositivo[Type.ANY];

        public Dispositivos() {
            for (int i = 1; i <= Type.MAILA; i++) {
                this.InDispositivo[i] = new Dispositivo();
            }
        }
    }

    class HacerPing2 implements Runnable {
        private int IP;
        private String contador;

        HacerPing2() {
        }

        public void SetData(String temp, int TempIP) {
            this.contador = temp;
            this.IP = TempIP;
        }

        public void run() {
            String str;
            String Temp;
            String MacTemporal;
            Exception e;
            Cursor cursor;
            int i3;
            String ipAddress = "null";
            String TextoFinal = BuildConfig.VERSION_NAME;
            if (InetAddress.getByName(this.contador).isReachable(3000)) {
                str = BuildConfig.VERSION_NAME;
                Temp = BuildConfig.VERSION_NAME;
                MacTemporal = BuildConfig.VERSION_NAME;
            } else {
                str = BuildConfig.VERSION_NAME;
                Temp = BuildConfig.VERSION_NAME;
                MacTemporal = BuildConfig.VERSION_NAME;
            }
            try {
                BufferedReader bufferedReader;
                BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"));
                while (true) {
                    try {
                        String line = br.readLine();
                        if (line == null) {
                            break;
                        }
                        String[] splitted = line.split(" +");
                        if (splitted != null && splitted.length >= 4 && this.contador.equals(splitted[0])) {
                            str = splitted[3];
                        }
                    } catch (Exception e2) {
                        e = e2;
                        bufferedReader = br;
                    }
                }
                bufferedReader = br;
            } catch (Exception e3) {
                e = e3;
                try {
                    e.printStackTrace();
                    if (!str.equals("00:00:00:00:00:00")) {
                        if (!str.equals(BuildConfig.VERSION_NAME)) {
                            MacTemporal = str;
                            cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.substring(0, MacTemporal.length() - 9).toUpperCase() + "'", null);
                            if (cursor.moveToFirst()) {
                                for (i3 = 1; cursor.getCount() >= i3; i3++) {
                                    Temp = cursor.getString(0);
                                    cursor.moveToNext();
                                }
                            }
                            cursor.close();
                            TextoFinal = "Hacer Ping 2: :" + this.contador + " " + str + " " + Temp + " \n";
                            Put(this.contador, str, Temp, null);
                        }
                    }
                } catch (IOException e4) {
                    e4.printStackTrace();
                }
                Red.ContadorDeIPs2++;
            }
            if (str.equals("00:00:00:00:00:00")) {
                if (str.equals(BuildConfig.VERSION_NAME)) {
                    MacTemporal = str;
                    cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.substring(0, MacTemporal.length() - 9).toUpperCase() + "'", null);
                    if (cursor.moveToFirst()) {
                        for (i3 = 1; cursor.getCount() >= i3; i3++) {
                            Temp = cursor.getString(0);
                            cursor.moveToNext();
                        }
                    }
                    cursor.close();
                    TextoFinal = "Hacer Ping 2: :" + this.contador + " " + str + " " + Temp + " \n";
                    Put(this.contador, str, Temp, null);
                }
            }
            Red.ContadorDeIPs2++;
        }

        public void Put(String TempIP, String TempMac, String TempVendor, String TempName) {
            Red.InDispositivos[0].InDispositivo[this.IP].IP = "Proceso 2 : " + TempIP;
            Red.InDispositivos[0].InDispositivo[this.IP].Mac = TempMac;
            Red.InDispositivos[0].InDispositivo[this.IP].Vendor = TempVendor;
        }
    }

    class HacerPing3 implements Runnable {
        private int IntIP;
        private String contador;

        HacerPing3() {
        }

        public void SetData(String temp, int TempIP) {
            this.contador = temp;
            this.IntIP = TempIP;
        }

        public void run() {
            Exception e;
            Cursor cursor;
            int i3;
            Red.ContadorDeIPs++;
            try {
                Process proc = Runtime.getRuntime().exec("ping -l 1 -n 1 -i 1 -W 1 " + this.contador);
            } catch (IOException e2) {
                e2.printStackTrace();
            }
            Red.ContadorDeIPs2++;
            String TempNombre = BuildConfig.VERSION_NAME;
            try {
                TempNombre = NbtAddress.getByName(this.contador).getHostName();
            } catch (UnknownHostException e3) {
                e3.printStackTrace();
            }
            try {
                Lookup lookup;
                SimpleResolver resolver;
                Record[] records;
                int i;
                PTRRecord ptr;
                String str = BuildConfig.VERSION_NAME;
                String Temp = BuildConfig.VERSION_NAME;
                String MacTemporal = BuildConfig.VERSION_NAME;
                try {
                    BufferedReader bufferedReader;
                    BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"));
                    while (true) {
                        try {
                            String line = br.readLine();
                            if (line == null) {
                                break;
                            }
                            String[] splitted = line.split(" +");
                            if (splitted != null && splitted.length >= 4 && this.contador.equals(splitted[0])) {
                                str = splitted[3];
                            }
                        } catch (Exception e4) {
                            e = e4;
                            bufferedReader = br;
                        }
                    }
                    bufferedReader = br;
                } catch (Exception e5) {
                    e = e5;
                    e.printStackTrace();
                    if (!str.equals("00:00:00:00:00:00")) {
                        if (!str.equals(BuildConfig.VERSION_NAME)) {
                            MacTemporal = str;
                            cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.substring(0, MacTemporal.length() - 9).toUpperCase() + "'", null);
                            if (cursor.moveToFirst()) {
                                for (i3 = 1; cursor.getCount() >= i3; i3++) {
                                    Temp = cursor.getString(0);
                                    cursor.moveToNext();
                                }
                            }
                            cursor.close();
                            Put(this.contador, str, Temp, TempNombre);
                            try {
                                lookup = new Lookup((this.IntIP + "." + MainActivity.ThirdNumberIP + "." + MainActivity.SecondNumberIP + "." + MainActivity.FirstNumberIP) + "." + "in-addr.arpa", 12);
                                resolver = new SimpleResolver();
                                resolver.setAddress(InetAddress.getByName(MainActivity.MyGateWay));
                                lookup.setResolver(resolver);
                                records = lookup.run();
                                if (lookup.getResult() != 0) {
                                    Put(this.contador, str, Temp, TempNombre);
                                    System.out.println("Failed lookup");
                                }
                                for (i = 0; i < records.length; i++) {
                                    if (records[i] instanceof PTRRecord) {
                                        ptr = records[i];
                                        if (records[0].rdataToString() != BuildConfig.VERSION_NAME) {
                                            if (TempNombre == BuildConfig.VERSION_NAME) {
                                            }
                                            if (TempNombre == BuildConfig.VERSION_NAME) {
                                                Put(this.contador, str, Temp, TempNombre);
                                            } else {
                                                Put(this.contador, str, Temp, records[0].rdataToString() + " " + Red.this.getResources().getString(R.string.Probablemente));
                                            }
                                        } else if (TempNombre == this.contador) {
                                            Put(this.contador, str, Temp, BuildConfig.VERSION_NAME);
                                        } else {
                                            Put(this.contador, str, Temp, TempNombre);
                                        }
                                    }
                                }
                                return;
                            } catch (Exception e6) {
                                Put(this.contador, str, Temp, TempNombre);
                                System.out.println("Exception: " + e6);
                                return;
                            }
                        }
                    }
                    return;
                }
                if (!str.equals("00:00:00:00:00:00")) {
                    return;
                }
                if (!str.equals(BuildConfig.VERSION_NAME)) {
                    MacTemporal = str;
                    cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.substring(0, MacTemporal.length() - 9).toUpperCase() + "'", null);
                    if (cursor.moveToFirst()) {
                        for (i3 = 1; cursor.getCount() >= i3; i3++) {
                            Temp = cursor.getString(0);
                            cursor.moveToNext();
                        }
                    }
                    cursor.close();
                    Put(this.contador, str, Temp, TempNombre);
                    lookup = new Lookup((this.IntIP + "." + MainActivity.ThirdNumberIP + "." + MainActivity.SecondNumberIP + "." + MainActivity.FirstNumberIP) + "." + "in-addr.arpa", 12);
                    resolver = new SimpleResolver();
                    resolver.setAddress(InetAddress.getByName(MainActivity.MyGateWay));
                    lookup.setResolver(resolver);
                    records = lookup.run();
                    if (lookup.getResult() != 0) {
                        for (i = 0; i < records.length; i++) {
                            if (records[i] instanceof PTRRecord) {
                                ptr = records[i];
                                if (records[0].rdataToString() != BuildConfig.VERSION_NAME) {
                                    if (TempNombre == BuildConfig.VERSION_NAME && !TempNombre.equals("0.0.0.0") && !TempNombre.equals(this.contador)) {
                                        Put(this.contador, str, Temp, TempNombre + "\n" + records[0].rdataToString() + " " + Red.this.getResources().getString(R.string.Probablemente));
                                    } else if (TempNombre == BuildConfig.VERSION_NAME) {
                                        Put(this.contador, str, Temp, records[0].rdataToString() + " " + Red.this.getResources().getString(R.string.Probablemente));
                                    } else {
                                        Put(this.contador, str, Temp, TempNombre);
                                    }
                                } else if (TempNombre == this.contador) {
                                    Put(this.contador, str, Temp, TempNombre);
                                } else {
                                    Put(this.contador, str, Temp, BuildConfig.VERSION_NAME);
                                }
                            }
                        }
                        return;
                    }
                    Put(this.contador, str, Temp, TempNombre);
                    System.out.println("Failed lookup");
                }
            } catch (Exception e62) {
                System.out.println("Exception: " + e62);
            }
        }

        public void Put(String TempIP, String TempMac, String TempVendor, String TempName) {
            Red.InDispositivos[0].InDispositivo[this.IntIP].IP = TempIP;
            Red.InDispositivos[0].InDispositivo[this.IntIP].Mac = TempMac;
            Red.InDispositivos[0].InDispositivo[this.IntIP].Vendor = TempVendor;
            String TempConocido = BuildConfig.VERSION_NAME;
            Cursor cursor = MainActivity.myDataBase.rawQuery("Select name from friend_list where mac = '" + TempMac + "'", null);
            if (cursor.moveToFirst()) {
                TempConocido = cursor.getString(0);
            }
            cursor.close();
            if (!TempConocido.equals(BuildConfig.VERSION_NAME) && TempConocido != null) {
                Red.InDispositivos[0].InDispositivo[this.IntIP].Name = TempConocido;
            } else if (!TempIP.equals(TempName) && TempName != "0.0.0.0") {
                Red.InDispositivos[0].InDispositivo[this.IntIP].Name = TempName;
            }
        }
    }

    class HacerPing implements Runnable {
        private int IP;
        private String contador;

        HacerPing() {
        }

        public void SetData(String temp, int TempIP) {
            this.contador = temp;
            this.IP = TempIP;
        }

        public void run() {
            String Temp;
            String MacTemporal;
            Cursor cursor;
            int i;
            Exception e2;
            BufferedReader bufferedReader;
            NbtAddress nbtAddress = null;
            String ipAddress = "null";
            String TextoFinal = BuildConfig.VERSION_NAME;
            try {
                nbtAddress = NbtAddress.getByName(this.contador);
                nbtAddress.getHostName();
                InetAddress in = InetAddress.getByName(this.contador);
                InetAddress address = nbtAddress.getInetAddress();
                Red.ContadorDeIPs2++;
                byte[] TempByte = nbtAddress.getMacAddress();
                Temp = BuildConfig.VERSION_NAME;
                MacTemporal = BuildConfig.VERSION_NAME;
                if (TempByte != null) {
                    StringBuffer hex = new StringBuffer(BuildConfig.VERSION_NAME);
                    for (int i2 = 0; i2 < TempByte.length; i2++) {
                        hex.append(Integer.toHexString((TempByte[i2] >> 4) & 15));
                        hex.append(Integer.toHexString(TempByte[i2] & 15));
                        if (i2 <= TempByte.length - 2) {
                            hex.append(":");
                        }
                    }
                    cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + hex.substring(0, hex.toString().length() - 9).toUpperCase() + "'", null);
                    if (cursor.moveToFirst()) {
                        for (i = 1; cursor.getCount() >= i; i++) {
                            Temp = cursor.getString(0);
                            cursor.moveToNext();
                        }
                    }
                    cursor.close();
                    Put(this.contador, hex.toString(), Temp, nbtAddress.getHostName());
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
                String mac = BuildConfig.VERSION_NAME;
                Temp = BuildConfig.VERSION_NAME;
                MacTemporal = BuildConfig.VERSION_NAME;
                try {
                    BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"));
                    while (true) {
                        try {
                            String line = br.readLine();
                            if (line == null) {
                                break;
                            }
                            String[] splitted = line.split(" +");
                            if (splitted != null && splitted.length >= 4 && this.contador.equals(splitted[0])) {
                                mac = splitted[3];
                            }
                        } catch (Exception e3) {
                            e2 = e3;
                            bufferedReader = br;
                        }
                    }
                    bufferedReader = br;
                } catch (Exception e4) {
                    e2 = e4;
                    e2.printStackTrace();
                    MacTemporal = mac;
                    try {
                        cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.substring(0, MacTemporal.length() - 9).toUpperCase() + "'", null);
                        if (cursor.moveToFirst()) {
                            for (i = 1; cursor.getCount() >= i; i++) {
                                Temp = cursor.getString(0);
                                cursor.moveToNext();
                            }
                        }
                        cursor.close();
                        TextoFinal = "Peor Caso : " + this.contador + " " + mac + " " + Temp + "\n";
                        Put(this.contador, mac, Temp, nbtAddress.getHostName());
                    } catch (Exception e22) {
                        e22.printStackTrace();
                        TextoFinal = "No se sabe... \n" + this.contador;
                    }
                    Red.ContadorDeIPs++;
                }
                if (!(mac.equals("00:00:00:00:00:00") || mac.equals(BuildConfig.VERSION_NAME) || this.contador.equals(MainActivity.MyIP))) {
                    MacTemporal = mac;
                    cursor = MainActivity.myDataBase2.rawQuery("Select field2 from vendor where field1 = '" + MacTemporal.substring(0, MacTemporal.length() - 9).toUpperCase() + "'", null);
                    if (cursor.moveToFirst()) {
                        for (i = 1; cursor.getCount() >= i; i++) {
                            Temp = cursor.getString(0);
                            cursor.moveToNext();
                        }
                    }
                    cursor.close();
                    TextoFinal = "Peor Caso : " + this.contador + " " + mac + " " + Temp + "\n";
                    Put(this.contador, mac, Temp, nbtAddress.getHostName());
                }
            }
            Red.ContadorDeIPs++;
        }

        public void Put(String TempIP, String TempMac, String TempVendor, String TempName) {
            Red.InDispositivos[0].InDispositivo[this.IP].IP = "Proceso 1 : " + TempIP;
            Red.InDispositivos[0].InDispositivo[this.IP].Mac = TempMac;
            Red.InDispositivos[0].InDispositivo[this.IP].Vendor = TempVendor;
            if (!TempIP.equals(TempName) && TempName != "0.0.0.0") {
                Red.InDispositivos[0].InDispositivo[this.IP].Name = TempName;
            }
        }
    }

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.red);
        if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
            PingFuncionando = false;
            Intent intent = new Intent(getApplicationContext(), FirstScreen.class);
            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
            startActivity(intent);
            finish();
        }
        this.Temp1 = (TextView) findViewById(R.id.textViewTitulo1);
        this.Temp2 = (TextView) findViewById(R.id.textViewTitulo2);
        this.Temp3 = (TextView) findViewById(R.id.textViewDisp);
        this.Temp4 = (TextView) findViewById(R.id.textViewDisp2);
        this.Temp5 = (TextView) findViewById(R.id.textviewNumDisp);
        this.Temp1.setText(getResources().getString(R.string.Titulo3));
        this.Temp2.setText(getResources().getString(R.string.Titulo4));
        this.Temp3.setText(getResources().getString(R.string.Titulo5));
        this.Temp4.setText(getResources().getString(R.string.Titulo6));
        this.Temp5.setText(" 0");
        connManager = (ConnectivityManager) getSystemService("connectivity");
        mWifi = connManager.getNetworkInfo(1);
        Lista = (ListView) findViewById(R.id.List);
        baseContext = getBaseContext();
        adapter = new SimpleAdapter(this.MyContext, list, R.layout.main_item_two_line_rows_dispositivos, new String[]{"line1", "line2", "line3", "line4", "line5", "line6", "line7", "line8", "image1"}, new int[]{R.id.text1, R.id.text2, R.id.text3, R.id.text4, R.id.text5, R.id.text6, R.id.text7, R.id.text8, R.id.image});
        Lista.setAdapter(adapter);
        wifi = (WifiManager) getSystemService("wifi");
        InDispositivos[0] = new Dispositivos();
        this.myProgressBar = (ProgressBar) findViewById(R.id.progressBar);
        this.myProgressBar.setMax(Type.TSIG);
        Temp13 = (TextView) findViewById(R.id.textView);
        TextoIntrusos = (TextView) findViewById(R.id.textView2);
        TextoIntrusos.setVisibility(8);
        this.myProgressBar2 = (ProgressBar) findViewById(R.id.progressBar2);
        Temp13.setVisibility(8);
        this.myProgressBar2.setVisibility(4);
        if (MainActivity.NeedScan) {
            MainActivity.NeedScan = false;
            OnClickActualizar(getCurrentFocus());
        } else {
            UpdateTextView();
        }
        Lista.setTextFilterEnabled(true);
        Lista.setSelector(17170445);
        Lista.setCacheColorHint(0);
        Lista.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                if (Red.PingFuncionando) {
                    Toast.makeText(Red.this.MyContext, Red.this.getResources().getString(R.string.EsperarScan), 0).show();
                    return;
                }
                MainActivity.IdDispositivoEscogido = position;
                Intent intent = new Intent(Red.this.getApplicationContext(), Dispositivo.class);
                intent.addFlags(SmbConstants.READ_CONTROL);
                Red.this.startActivity(intent);
            }
        });
        AdView adView = new AdView(this);
        adView.setAdUnitId("ca-app-pub-2885006023541960/8905524538");
        adView.setAdSize(AdSize.SMART_BANNER);
        adView = (AdView) findViewById(R.id.adView);
        adView.loadAd(new Builder().build());
        final AdView finalAdView = adView;
        adView.setAdListener(new AdListener() {
            public void onAdLoaded() {
                int height = finalAdView.getHeight();
                RelativeLayout relativeLayout = new RelativeLayout(Red.this.MyContext);
                ((RelativeLayout) Red.this.findViewById(R.id.Todo2)).setPadding(0, 0, 0, height + 1);
            }
        });
    }

    protected void onStart() {
        super.onStart();
    }

    protected void onResume() {
        getWindow().addFlags(Flags.FLAG8);
        UpdateTextView();
        if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
            PingFuncionando = false;
            Intent intent = new Intent(getApplicationContext(), FirstScreen.class);
            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
            startActivity(intent);
            finish();
        }
        AdView adView = new AdView(this);
        adView.setAdUnitId("ca-app-pub-2885006023541960/8905524538");
        adView.setAdSize(AdSize.SMART_BANNER);
        adView = (AdView) findViewById(R.id.adView);
        adView.loadAd(new Builder().build());
        final AdView finalAdView = adView;
        adView.setAdListener(new AdListener() {
            public void onAdLoaded() {
                int height = finalAdView.getHeight();
                RelativeLayout relativeLayout = new RelativeLayout(Red.this.MyContext);
                ((RelativeLayout) Red.this.findViewById(R.id.Todo2)).setPadding(0, 0, 0, height + 1);
            }
        });
        if (MainActivity.ToastHelper == 1) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.NombreActualizado), 0).show();
        } else if (MainActivity.ToastHelper == 3) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.DispQuitadoConocido), 0).show();
        } else if (MainActivity.ToastHelper == 2) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.DispPuestoConocido), 0).show();
        }
        MainActivity.ToastHelper = 0;
        super.onResume();
    }

    protected void onPause() {
        super.onPause();
    }

    protected void onStop() {
        super.onStop();
    }

    protected void onRestart() {
        super.onRestart();
    }

    protected void onDestroy() {
        super.onDestroy();
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (VERSION.SDK_INT < 5 && keyCode == 4 && event.getRepeatCount() == 0) {
            onBackPressed();
        }
        return super.onKeyDown(keyCode, event);
    }

    public void onBackPressed() {
        if (PingFuncionando || this.WifiDesconectada) {
            Toast.makeText(this, getResources().getString(R.string.EsperarScan), 0).show();
        } else if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
            PingFuncionando = false;
            MainActivity.interstitial2.loadAd(new Builder().build());
            executor3.shutdownNow();
            intent = new Intent(getApplicationContext(), FirstScreen.class);
            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
            startActivity(intent);
            finish();
        } else {
            PingFuncionando = false;
            MainActivity.interstitial2.loadAd(new Builder().build());
            executor3.shutdownNow();
            intent = new Intent(getApplicationContext(), MainActivity.class);
            intent.addFlags(SmbConstants.READ_CONTROL);
            startActivity(intent);
            finish();
        }
    }

    public void UpdateTextView() {
        boolean HayDesconocidos = false;
        int Temp = 0;
        list.clear();
        mWifi = connManager.getNetworkInfo(1);
        if (this.WifiDesconectada) {
            Temp13.setText(getResources().getString(R.string.PrepRed));
        }
        for (int i = 1; i <= Type.MAILA; i++) {
            if (InDispositivos[0].InDispositivo[i].IP != null) {
                try {
                    HashMap<String, String> item = new HashMap();
                    item.put("line1", "IP: ");
                    item.put("line2", InDispositivos[0].InDispositivo[i].IP);
                    item.put("line3", getResources().getString(R.string.Fabricante) + ": ");
                    item.put("line4", InDispositivos[0].InDispositivo[i].Vendor);
                    item.put("line5", getResources().getString(R.string.NetBios) + ": ");
                    if (InDispositivos[0].InDispositivo[i].Name == null) {
                        item.put("line6", " - ");
                    } else {
                        item.put("line6", InDispositivos[0].InDispositivo[i].Name);
                    }
                    item.put("line7", getResources().getString(R.string.MACAdress) + ": ");
                    item.put("line8", InDispositivos[0].InDispositivo[i].Mac);
                    if (InDispositivos[0].InDispositivo[i].IP.equals(MainActivity.MyIP)) {
                        item.put("image1", Integer.toString(R.drawable.midispositivo));
                        item.put("line6", getResources().getString(R.string.EsteEsTuDispositivo));
                        item.put("line5", BuildConfig.VERSION_NAME);
                    } else if (InDispositivos[0].InDispositivo[i].IP.equals(MainActivity.MyGateWay)) {
                        item.put("image1", Integer.toString(R.drawable.router));
                        item.put("line6", getResources().getString(R.string.GateWay2));
                        item.put("line5", BuildConfig.VERSION_NAME);
                    } else {
                        boolean TempConocido = false;
                        Cursor cursor = MainActivity.myDataBase.rawQuery("Select mac from friend_list where mac = '" + InDispositivos[0].InDispositivo[i].Mac + "'", null);
                        if (cursor.moveToFirst()) {
                            for (int i2 = 1; cursor.getCount() >= i2; i2++) {
                                TempConocido = true;
                                cursor.moveToNext();
                            }
                        }
                        cursor.close();
                        if (TempConocido) {
                            if (InDispositivos[0].InDispositivo[i].Vendor != null) {
                                item.put("line4", InDispositivos[0].InDispositivo[i].Vendor);
                            } else {
                                item.put("line4", " - ");
                            }
                            item.put("image1", Integer.toString(R.drawable.conocido));
                        } else {
                            HayDesconocidos = true;
                            item.put("image1", Integer.toString(R.drawable.desconocido));
                        }
                    }
                    list.add(item);
                    Temp++;
                    runOnUiThread(new Runnable() {
                        public void run() {
                            Red.adapter.notifyDataSetChanged();
                        }
                    });
                } catch (Exception e) {
                }
                if (ContadorDeIPs2 == 0) {
                    Temp13.setText(getResources().getString(R.string.PrepRed));
                    if (ContadorDeIPs >= Type.MAILA) {
                        Intent intent;
                        if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
                            PingFuncionando = false;
                            intent = new Intent(getApplicationContext(), FirstScreen.class);
                            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
                            startActivity(intent);
                            finish();
                        } else {
                            intent = new Intent(getApplicationContext(), MainActivity.class);
                            intent.addFlags(SmbConstants.READ_CONTROL);
                            startActivity(intent);
                            finish();
                        }
                    }
                } else if (ContadorDeIPs2 <= 150) {
                    Temp13.setText(getResources().getString(R.string.ActualizLista));
                } else if (executor3.isTerminated()) {
                    ScanEnCurso = false;
                    Temp13.setText(getResources().getString(R.string.DispEncontrados) + ContadorDispositivosEncontrados);
                    Temp13.setVisibility(8);
                    if (!this.PubliTemp) {
                        this.PubliTemp = true;
                        MainActivity.interstitial.loadAd(new Builder().build());
                        AdView adView = new AdView(this);
                        adView.setAdUnitId("ca-app-pub-2885006023541960/8905524538");
                        adView.setAdSize(AdSize.SMART_BANNER);
                        adView = (AdView) findViewById(R.id.adView);
                        adView.loadAd(new Builder().build());
                        final AdView finalAdView = adView;
                        adView.setAdListener(new AdListener() {
                            public void onAdLoaded() {
                                int height = finalAdView.getHeight();
                                RelativeLayout relativeLayout = new RelativeLayout(Red.this.MyContext);
                                ((RelativeLayout) Red.this.findViewById(R.id.Todo2)).setPadding(0, 0, 0, height + 1);
                            }
                        });
                    }
                    if (HayDesconocidos) {
                        TextoIntrusos.setVisibility(0);
                        TextoIntrusos.setText(getResources().getString(R.string.AlertDesconocidos));
                        this.myProgressBar.setVisibility(8);
                        this.myProgressBar2.setVisibility(4);
                    } else {
                        TextoIntrusos.setVisibility(8);
                        this.myProgressBar.setVisibility(8);
                        this.myProgressBar2.setVisibility(4);
                    }
                } else {
                    Temp13.setText(getResources().getString(R.string.FinalizandoProceso));
                }
            }
        }
        ContadorDispositivosEncontrados = Temp;
        this.Temp5.setText(" " + ContadorDispositivosEncontrados);
    }

    public void OnClickActualizar(View v) {
        this.PubliTemp = false;
        WifiInfo wifiInfo = wifi.getConnectionInfo();
        if (!wifi.isWifiEnabled() || MainActivity.MyIP.equals("0.0.0.0")) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.RedNoLista), 0).show();
        } else if (PingFuncionando || ScanEnCurso) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.EsperarScan), 0).show();
        } else {
            StartRefresh = System.currentTimeMillis();
            ScanEnCurso = true;
            wifi.setWifiEnabled(false);
            wifi.setWifiEnabled(true);
            wifi.reassociate();
            this.Temp5.setText(" 0");
            list.clear();
            InDispositivos[0] = new Dispositivos();
            this.WifiDesconectada = true;
            UpdateTextView();
            this.WifiDesconectada = false;
            TextoIntrusos.setVisibility(8);
            Temp13.setVisibility(0);
            this.myProgressBar.setVisibility(0);
            this.myProgressBar2.setVisibility(0);
            this.myProgressBar.setMax(Type.TSIG);
            this.myProgressBar.setProgress(0);
            this.TempContPreparandoRed = 0;
            final Timer timer = new Timer();
            timer.scheduleAtFixedRate(new TimerTask() {
                public void run() {
                    if (Red.PingFuncionando) {
                        try {
                            timer.cancel();
                            return;
                        } catch (Throwable throwable) {
                            throwable.printStackTrace();
                            return;
                        }
                    }
                    Red.wifi.setWifiEnabled(true);
                    Red red = Red.this;
                    red.TempContPreparandoRed++;
                    Red.this.myProgressBar.setProgress(Red.this.TempContPreparandoRed);
                    if (System.currentTimeMillis() - Red.StartRefresh >= 30000) {
                        Red.ScanEnCurso = false;
                        Intent intent;
                        if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
                            Red.PingFuncionando = false;
                            intent = new Intent(Red.this.getApplicationContext(), FirstScreen.class);
                            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
                            Red.this.startActivity(intent);
                            Red.this.finish();
                        } else {
                            intent = new Intent(Red.this.getApplicationContext(), MainActivity.class);
                            intent.addFlags(SmbConstants.READ_CONTROL);
                            Red.this.startActivity(intent);
                            Red.this.finish();
                        }
                        try {
                            timer.cancel();
                            return;
                        } catch (Throwable throwable2) {
                            throwable2.printStackTrace();
                            return;
                        }
                    }
                    Red.this.HacerScan();
                }
            }, 0, 600);
        }
    }

    public void HacerScan() {
        mWifi = connManager.getNetworkInfo(1);
        if (PingFuncionando) {
            Toast.makeText(this.MyContext, getResources().getString(R.string.EsperarScan), 0).show();
        } else if (!mWifi.isConnected() || this.WifiDesconectada) {
            this.WifiDesconectada = true;
            if (mWifi.isConnected()) {
                this.WifiDesconectada = false;
                new Thread(this.myThread).start();
                ContadorDeIPs = 0;
                ContadorDeIPs2 = 0;
                executor3 = new ThreadPoolExecutor(Flags.FLAG8, Type.ANY, 240, TimeUnit.SECONDS, new LinkedBlockingQueue());
                if (VERSION.SDK_INT > 9) {
                    StrictMode.setThreadPolicy(new ThreadPolicy.Builder().permitAll().build());
                }
                IPTemp = MainActivity.MyIP;
                new Thread() {
                    public void run() {
                        do {
                            try {
                                if (!isInterrupted()) {
                                    Thread.sleep(500);
                                    Red.this.runOnUiThread(new Runnable() {
                                        public void run() {
                                            Red.this.UpdateTextView();
                                            if (Red.executor3.isTerminated()) {
                                                Red.executor3.shutdownNow();
                                                Red.this.UpdateTextView();
                                                Red.PingFuncionando = false;
                                                try {
                                                    finalize();
                                                } catch (Throwable throwable) {
                                                    throwable.printStackTrace();
                                                }
                                            }
                                        }
                                    });
                                } else {
                                    return;
                                }
                            } catch (InterruptedException e) {
                                return;
                            }
                        } while (Red.PingFuncionando);
                        throw new InterruptedException();
                    }
                }.start();
                IPActual = 1;
                PingFuncionando = true;
                ContadorDispositivosEncontrados = 0;
                this.TiempoAlEmpezar = System.currentTimeMillis();
                int ip = wifi.getConnectionInfo().getIpAddress();
                MainActivity.MyIP = String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 24) & Type.ANY)});
                MainActivity.PartialIP = String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)}) + "." + String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)}) + ".";
                MainActivity.FirstNumberIP = String.format("%d", new Object[]{Integer.valueOf(ip & Type.ANY)});
                MainActivity.SecondNumberIP = String.format("%d", new Object[]{Integer.valueOf((ip >> 8) & Type.ANY)});
                MainActivity.ThirdNumberIP = String.format("%d", new Object[]{Integer.valueOf((ip >> 16) & Type.ANY)});
                MainActivity.LastNumberIP = String.format("%d", new Object[]{Integer.valueOf((ip >> 24) & Type.ANY)});
                for (int i2 = 1; i2 <= Type.MAILA; i2++) {
                    IPTemp = MainActivity.PartialIP + i2;
                    if (IPTemp.equals(MainActivity.MyIP)) {
                        InDispositivos[0].InDispositivo[i2].IP = IPTemp;
                        InDispositivos[0].InDispositivo[i2].Mac = MainActivity.MyMac;
                        InDispositivos[0].InDispositivo[i2].Vendor = MainActivity.MyVendor;
                        InDispositivos[0].InDispositivo[i2].Name = getResources().getString(R.string.EsteDisp);
                        ContadorDispositivosEncontrados++;
                    } else {
                        IP3[i2] = new HacerPing3();
                        IP3[i2].SetData(IPTemp, i2);
                        executor3.execute(IP3[i2]);
                    }
                }
                executor3.shutdown();
            }
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
                                Red.this.UpdateTextView();
                                return;
                            default:
                                return;
                        }
                    }
                };
                AlertDialog.Builder builder = new AlertDialog.Builder(this.MyContext);
                builder.setPositiveButton(getResources().getString(R.string.Yes), dialogClickListener).setTitle(getResources().getString(R.string.TituloBorrar)).setIcon(17301642).setNegativeButton(getResources().getString(R.string.Cancelar), dialogClickListener).setCancelable(false).setMessage(getResources().getString(R.string.TextoBorrarLista));
                builder.show();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }
}
