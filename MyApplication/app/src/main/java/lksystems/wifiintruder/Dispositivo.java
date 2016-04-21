package lksystems.wifiintruder;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.SimpleAdapter;
import android.widget.TextView;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest.Builder;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import java.util.ArrayList;
import java.util.HashMap;
import org.xbill.DNS.Type;

public class Dispositivo extends Activity {
    Button Boton1;
    ListView Lista;
    Context MyContext = this;
    EditText Name;
    int QueEs = 0;
    TextView Temp1;
    TextView Temp2;
    TextView Temp3;
    TextView Temp4;
    TextView Temp5;
    TextView Temp6;
    int TempContador = 0;
    int TempI;
    String TempIP;
    String TempMac = BuildConfig.VERSION_NAME;
    String TempName;
    String TempVendor;
    SimpleAdapter adapter;
    ArrayList<HashMap<String, String>> list = new ArrayList();

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.dispositivo);
        this.Temp1 = (TextView) findViewById(R.id.textViewTitulo1);
        this.Temp2 = (TextView) findViewById(R.id.textViewTitulo2);
        this.Temp3 = (TextView) findViewById(R.id.textViewRed);
        this.Temp5 = (TextView) findViewById(R.id.textViewRed2);
        this.Temp6 = (TextView) findViewById(R.id.textview1);
        this.Temp1.setText(getResources().getString(R.string.Titulo7));
        this.Temp2.setText(getResources().getString(R.string.Titulo8));
        this.list.clear();
        this.Lista = (ListView) findViewById(R.id.List);
        this.Lista.setDividerHeight(0);
        this.Lista.setDivider(null);
        this.adapter = new SimpleAdapter(this.MyContext, this.list, R.layout.main_item_two_line_rows_dispositivo, new String[]{"line1", "line2"}, new int[]{R.id.text1, R.id.text2});
        this.Lista.setAdapter(this.adapter);
        this.Lista.setSelector(17170445);
        this.Lista.setCacheColorHint(0);
        this.Boton1 = (Button) findViewById(R.id.button);
        this.Name = (EditText) findViewById(R.id.editText);
        this.Name.setHint(getResources().getString(R.string.PonerNombre));
    }

    protected void onStart() {
        super.onStart();
    }

    protected void onResume() {
        this.TempContador = 0;
        if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
            Intent intent = new Intent(getApplicationContext(), MainActivity.class);
            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
            startActivity(intent);
            super.finish();
        }
        int i = 1;
        while (i <= Type.MAILA) {
            if (MainActivity.Killed && Red.InDispositivos[0].InDispositivo[i].IP != null) {
                if (Red.InDispositivos[0].InDispositivo[i].Name == null) {
                    Red.InDispositivos[0].InDispositivo[i].Name = BuildConfig.VERSION_NAME;
                }
                if (Red.InDispositivos[0].InDispositivo[i].Vendor == null) {
                    Red.InDispositivos[0].InDispositivo[i].Vendor = BuildConfig.VERSION_NAME;
                }
                if (this.TempContador == MainActivity.IdDispositivoEscogido) {
                    this.TempI = i;
                    this.TempMac = Red.InDispositivos[0].InDispositivo[i].Mac;
                    HashMap hashMap;
                    HashMap<String, String> item;
                    if (Red.InDispositivos[0].InDispositivo[i].IP.equals(MainActivity.MyIP)) {
                        this.QueEs = 0;
                        this.Name.setVisibility(4);
                        try {
                            this.list.clear();
                            hashMap = new HashMap();
                            item = new HashMap();
                            item.put("line1", "IP: ");
                            item.put("line2", MainActivity.MyIP);
                            this.list.add(item);
                            item = new HashMap();
                            item.put("line1", getResources().getString(R.string.Fabricante) + ": ");
                            item.put("line2", MainActivity.MyVendor);
                            this.list.add(item);
                            item = new HashMap();
                            item.put("line1", getResources().getString(R.string.MACAdress) + " ");
                            item.put("line2", MainActivity.MyMac);
                            item.put("line3", "--------------");
                            this.list.add(item);
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Dispositivo.this.adapter.notifyDataSetChanged();
                                }
                            });
                        } catch (Exception e) {
                        }
                        this.Temp3.setText(getResources().getString(R.string.EsteEsTuDispositivo));
                        this.Temp5.setText(BuildConfig.VERSION_NAME);
                        this.Temp6.setText(BuildConfig.VERSION_NAME);
                    } else if (Red.InDispositivos[0].InDispositivo[i].IP.equals(MainActivity.MyGateWay)) {
                        this.QueEs = 1;
                        this.Name.setVisibility(4);
                        this.list.clear();
                        hashMap = new HashMap();
                        item = new HashMap();
                        item.put("line1", "IP: ");
                        item.put("line2", Red.InDispositivos[0].InDispositivo[i].IP);
                        this.list.add(item);
                        item = new HashMap();
                        item.put("line1", getResources().getString(R.string.Fabricante) + ": ");
                        item.put("line2", Red.InDispositivos[0].InDispositivo[i].Vendor);
                        this.list.add(item);
                        String TempConocido = Red.InDispositivos[0].InDispositivo[i].Name;
                        cursor = MainActivity.myDataBase.rawQuery("Select name from friend_list where mac = '" + Red.InDispositivos[0].InDispositivo[i].Mac + "'", null);
                        if (cursor.moveToFirst() && cursor.getString(0) != BuildConfig.VERSION_NAME) {
                            TempConocido = cursor.getString(0);
                        }
                        cursor.close();
                        item = new HashMap();
                        item.put("line1", getResources().getString(R.string.NetBios) + ": ");
                        if (Red.InDispositivos[0].InDispositivo[i].Name.equals(BuildConfig.VERSION_NAME)) {
                            item.put("line2", " - ");
                        } else {
                            item.put("line2", TempConocido);
                        }
                        this.list.add(item);
                        item = new HashMap();
                        item.put("line1", "MacAddess: ");
                        item.put("line2", Red.InDispositivos[0].InDispositivo[i].Mac);
                        this.list.add(item);
                        runOnUiThread(new Runnable() {
                            public void run() {
                                Dispositivo.this.adapter.notifyDataSetChanged();
                            }
                        });
                        this.Temp3.setText(getResources().getString(R.string.GateWay2));
                        this.Temp5.setText(BuildConfig.VERSION_NAME);
                        this.Temp6.setText(getResources().getString(R.string.Router));
                    } else {
                        boolean TempConocido2 = false;
                        cursor = MainActivity.myDataBase.rawQuery("Select mac from friend_list where mac = '" + Red.InDispositivos[0].InDispositivo[i].Mac + "'", null);
                        if (cursor.moveToFirst()) {
                            for (int i2 = 1; cursor.getCount() >= i2; i2++) {
                                TempConocido2 = true;
                                cursor.moveToNext();
                            }
                        }
                        cursor.close();
                        String TempConocido22;
                        if (TempConocido2) {
                            this.QueEs = 2;
                            this.Name.setVisibility(0);
                            this.list.clear();
                            hashMap = new HashMap();
                            item = new HashMap();
                            item.put("line1", "IP: ");
                            item.put("line2", Red.InDispositivos[0].InDispositivo[i].IP);
                            this.list.add(item);
                            this.TempIP = Red.InDispositivos[0].InDispositivo[i].IP;
                            item = new HashMap();
                            item.put("line1", getResources().getString(R.string.Fabricante) + ": ");
                            item.put("line2", Red.InDispositivos[0].InDispositivo[i].Vendor);
                            this.list.add(item);
                            this.TempVendor = Red.InDispositivos[0].InDispositivo[i].Vendor;
                            item = new HashMap();
                            item.put("line1", getResources().getString(R.string.NetBios) + ": ");
                            if (Red.InDispositivos[0].InDispositivo[i].Name.equals(BuildConfig.VERSION_NAME)) {
                                item.put("line2", " - ");
                            } else {
                                item.put("line2", Red.InDispositivos[0].InDispositivo[i].Name);
                            }
                            this.list.add(item);
                            this.TempName = Red.InDispositivos[0].InDispositivo[i].Name;
                            TempConocido22 = Red.InDispositivos[0].InDispositivo[i].Name;
                            cursor = MainActivity.myDataBase.rawQuery("Select name from friend_list where mac = '" + Red.InDispositivos[0].InDispositivo[i].Mac + "'", null);
                            if (cursor.moveToFirst() && cursor.getString(0) != BuildConfig.VERSION_NAME) {
                                TempConocido22 = cursor.getString(0);
                            }
                            cursor.close();
                            this.Name.setHint(getResources().getString(R.string.CambiarNombre));
                            item = new HashMap();
                            item.put("line1", "MacAddess: ");
                            item.put("line2", Red.InDispositivos[0].InDispositivo[i].Mac);
                            this.list.add(item);
                            this.TempMac = Red.InDispositivos[0].InDispositivo[i].Mac;
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Dispositivo.this.adapter.notifyDataSetChanged();
                                }
                            });
                            this.Temp3.setText(getResources().getString(R.string.Conocido));
                            this.Temp5.setText(getResources().getString(R.string.Conocido2));
                            this.Temp6.setText(getResources().getString(R.string.DispConocido2));
                        } else {
                            this.QueEs = 3;
                            this.Name.setVisibility(0);
                            this.list.clear();
                            hashMap = new HashMap();
                            item = new HashMap();
                            item.put("line1", "IP: ");
                            item.put("line2", Red.InDispositivos[0].InDispositivo[i].IP);
                            this.list.add(item);
                            item = new HashMap();
                            item.put("line1", getResources().getString(R.string.Fabricante) + ": ");
                            item.put("line2", Red.InDispositivos[0].InDispositivo[i].Vendor);
                            this.list.add(item);
                            TempConocido22 = Red.InDispositivos[0].InDispositivo[i].Name;
                            cursor = MainActivity.myDataBase.rawQuery("Select name from friend_list where mac = '" + Red.InDispositivos[0].InDispositivo[i].Mac + "'", null);
                            if (cursor.moveToFirst() && cursor.getString(0) != BuildConfig.VERSION_NAME) {
                                TempConocido22 = cursor.getString(0);
                            }
                            cursor.close();
                            item = new HashMap();
                            item.put("line1", getResources().getString(R.string.NetBios) + ": ");
                            if (Red.InDispositivos[0].InDispositivo[i].Name.equals(BuildConfig.VERSION_NAME)) {
                                item.put("line2", " - ");
                            } else {
                                item.put("line2", TempConocido22);
                            }
                            this.list.add(item);
                            item = new HashMap();
                            item.put("line1", "MacAddess: ");
                            item.put("line2", Red.InDispositivos[0].InDispositivo[i].Mac);
                            this.list.add(item);
                            runOnUiThread(new Runnable() {
                                public void run() {
                                    Dispositivo.this.adapter.notifyDataSetChanged();
                                }
                            });
                            this.Temp3.setText(getResources().getString(R.string.Desconocido));
                            this.Temp5.setText(getResources().getString(R.string.Desconocido2));
                            this.Temp6.setText(getResources().getString(R.string.DispDesconocido2));
                        }
                    }
                    i = Type.ANY;
                }
                this.TempContador++;
            }
            i++;
        }
        if (this.QueEs == 0 || this.QueEs == 1) {
            this.Boton1.setText(getResources().getString(R.string.Retroceder));
        } else if (this.QueEs == 2) {
            this.Boton1.setText(getResources().getString(R.string.DelDevice));
        } else {
            this.Boton1.setText(getResources().getString(R.string.AddDevice));
        }
        AdView adView = new AdView(this);
        adView.setAdUnitId("ca-app-pub-2885006023541960/1382257735");
        adView.setAdSize(AdSize.SMART_BANNER);
        adView = (AdView) findViewById(R.id.adView);
        adView.loadAd(new Builder().build());
        final AdView finalAdView = adView;
        adView.setAdListener(new AdListener() {
            public void onAdLoaded() {
                int height = finalAdView.getHeight();
                RelativeLayout relativeLayout = new RelativeLayout(Dispositivo.this.MyContext);
                ((RelativeLayout) Dispositivo.this.findViewById(R.id.Todo2)).setPadding(0, 0, 0, height + 1);
            }
        });
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

    public void OnClickButton(View v) {
        Intent intent;
        if (this.QueEs == 3) {
            MainActivity.NumberOnList++;
            this.Name.toString().trim().equals(BuildConfig.VERSION_NAME);
            if (this.Name.length() >= 1) {
                Red.InDispositivos[0].InDispositivo[this.TempI].Name = this.Name.getText().toString();
                MainActivity.BD.insertDispositivo(this.TempMac, this.Name.getText().toString());
            } else {
                MainActivity.BD.insertDispositivo(this.TempMac, BuildConfig.VERSION_NAME);
            }
            MainActivity.ToastHelper = 2;
            if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
                intent = new Intent(getApplicationContext(), FirstScreen.class);
                intent.addFlags(SmbConstants.GENERIC_EXECUTE);
                startActivity(intent);
                finish();
                return;
            }
            intent = new Intent(this.MyContext, Red.class);
            intent.addFlags(SmbConstants.READ_CONTROL);
            startActivity(intent);
            finish();
        } else if (this.QueEs == 2) {
            this.TempName = Red.InDispositivos[0].InDispositivo[this.TempI].Name;
            String TempConocido2 = Red.InDispositivos[0].InDispositivo[this.TempI].Name;
            Cursor cursor = MainActivity.myDataBase.rawQuery("Select name from friend_list where mac = '" + Red.InDispositivos[0].InDispositivo[this.TempI].Mac + "'", null);
            if (!(!cursor.moveToFirst() || cursor.getString(0) == BuildConfig.VERSION_NAME || cursor.getString(0) == null)) {
                TempConocido2 = cursor.getString(0);
            }
            cursor.close();
            if (TempConocido2.equals(Red.InDispositivos[0].InDispositivo[this.TempI].Name)) {
                Red.InDispositivos[0].InDispositivo[this.TempI].Name = "( " + this.TempName + " )";
            }
            MainActivity.NumberOnList--;
            MainActivity.BD.removeDispositivo(this.TempMac);
            MainActivity.ToastHelper = 3;
            if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
                intent = new Intent(getApplicationContext(), FirstScreen.class);
                intent.addFlags(SmbConstants.GENERIC_EXECUTE);
                startActivity(intent);
                finish();
                return;
            }
            intent = new Intent(this.MyContext, Red.class);
            intent.addFlags(SmbConstants.READ_CONTROL);
            startActivity(intent);
            finish();
        } else if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
            intent = new Intent(getApplicationContext(), FirstScreen.class);
            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
            startActivity(intent);
            finish();
        } else {
            intent = new Intent(this.MyContext, Red.class);
            intent.addFlags(SmbConstants.READ_CONTROL);
            startActivity(intent);
            finish();
        }
    }

    public void onBackPressed() {
        if (MainActivity.MyIP.equals("0.0.0.0") || !MainActivity.PrimeraVezFirstScreen) {
            Intent intent = new Intent(getApplicationContext(), MainActivity.class);
            intent.addFlags(SmbConstants.GENERIC_EXECUTE);
            startActivity(intent);
            finish();
            return;
        }
        this.Name.toString().trim().equals(BuildConfig.VERSION_NAME);
        if (this.Name.length() >= 1 && this.QueEs == 2) {
            MainActivity.BD.removeDispositivo(this.TempMac);
            MainActivity.BD.insertDispositivo(this.TempMac, this.Name.getText().toString());
            Red.InDispositivos[0].InDispositivo[this.TempI].Name = this.Name.getText().toString();
            MainActivity.ToastHelper = 1;
        }
        intent = new Intent(getApplicationContext(), Red.class);
        intent.addFlags(SmbConstants.READ_CONTROL);
        startActivity(intent);
        finish();
    }
}
