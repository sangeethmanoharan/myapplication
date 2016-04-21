package lksystems.wifiintruder;

import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.text.Html;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import jcifs.netbios.NbtException;
import org.xbill.DNS.Tokenizer;
import org.xbill.DNS.Type;
import org.xbill.DNS.WKSRecord.Protocol;
import org.xbill.DNS.WKSRecord.Service;
import org.xbill.DNS.Zone;

public class FirstScreen extends Activity {
    static boolean TempPubli = false;
    Button Boton1;
    int ContadorFirstScreen;
    Context MyContext = this;
    boolean Opinar = false;
    TextView Temp1;
    TextView Temp2;
    WifiManager wifi;

    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.first_screen);
        TempPubli = true;
        if (MainActivity.Killed) {
            this.Boton1 = (Button) findViewById(R.id.buttonreintentar);
            this.Boton1.setVisibility(8);
            this.Temp1 = (TextView) findViewById(R.id.textfirstscreen);
            this.Temp2 = (TextView) findViewById(R.id.textView);
            this.Temp2.setText("v " + getResources().getString(R.string.app_version));
            try {
                MainActivity.BD2.open();
            } catch (Throwable th) {
                Intent intent = new Intent(getApplicationContext(), MainActivity.class);
                intent.addFlags(SmbConstants.GENERIC_EXECUTE);
                startActivity(intent);
                finish();
            }
            Cursor cursor = MainActivity.myDataBase.rawQuery("Select version from settings", null);
            if (cursor.moveToFirst()) {
                String Temp2 = cursor.getString(0);
                if (cursor.getString(0).equals("3.9")) {
                    MainActivity.VersionApp = 40;
                }
            } else {
                MainActivity.BD2.removeSettings();
                MainActivity.BD2.insertSettings("3.9", 0);
                MainActivity.VersionApp = 40;
            }
            cursor.close();
            cursor = MainActivity.myDataBase.rawQuery("Select votar from settings", null);
            if (cursor.moveToFirst()) {
                MainActivity.BD2.removeSettings();
                MainActivity.BD2.insertSettings("3.9", cursor.getInt(0) + 1);
                if (cursor.getInt(0) == 5) {
                    MostrarVotar();
                } else {
                    if (!false) {
                        Start();
                    }
                    MainActivity.BD2.close();
                }
            }
            cursor.close();
            return;
        }
        intent = new Intent(getApplicationContext(), MainActivity.class);
        intent.addFlags(SmbConstants.GENERIC_EXECUTE);
        startActivity(intent);
        finish();
    }

    protected void onResume() {
        if (this.Opinar) {
            Start();
        }
        super.onResume();
    }

    public void Start() {
        this.ContadorFirstScreen = 16;
        this.wifi = (WifiManager) getSystemService("wifi");
        if (this.wifi.isWifiEnabled()) {
            Letras();
            return;
        }
        this.Temp1.setText(getResources().getString(R.string.SinWifi));
        this.Boton1.setVisibility(0);
        Toast.makeText(getApplicationContext(), getResources().getString(R.string.ActivandoWifi), 0).show();
        this.wifi.setWifiEnabled(true);
    }

    public void OnClickReintentar(View v) {
        this.wifi = (WifiManager) getSystemService("wifi");
        if (this.wifi.isWifiEnabled()) {
            Letras();
            return;
        }
        this.Temp1.setText(getResources().getString(R.string.SinWifi));
        this.Boton1.setVisibility(0);
        Toast.makeText(getApplicationContext(), getResources().getString(R.string.ActivandoWifi), 0).show();
        this.wifi.setWifiEnabled(true);
    }

    public void Letras() {
        this.Boton1.setVisibility(8);
        new Thread() {
            public void run() {
                do {
                    try {
                        if (!isInterrupted()) {
                            Thread.sleep(120);
                            FirstScreen.this.runOnUiThread(new Runnable() {
                                public void run() {
                                    FirstScreen.this.FirstScreen();
                                }
                            });
                        } else {
                            return;
                        }
                    } catch (InterruptedException e) {
                        return;
                    }
                } while (FirstScreen.this.ContadorFirstScreen < 20);
                MainActivity.PrimeraVezFirstScreen = true;
                Intent intent = new Intent(FirstScreen.this.getApplicationContext(), MainActivity.class);
                intent.addFlags(SmbConstants.READ_CONTROL);
                FirstScreen.this.startActivity(intent);
                FirstScreen.this.finish();
                throw new InterruptedException();
            }
        }.start();
    }

    public void FirstScreen() {
        switch (this.ContadorFirstScreen) {
            case Tokenizer.EOF /*0*/:
            case Type.MF /*4*/:
            case Protocol.EGP /*8*/:
                this.Temp1.setText(getResources().getString(R.string.ComprobandoRed) + "   ");
                break;
            case Zone.PRIMARY /*1*/:
            case Service.RJE /*5*/:
            case Service.DISCARD /*9*/:
                this.Temp1.setText(getResources().getString(R.string.ComprobandoRed) + ".  ");
                break;
            case Zone.SECONDARY /*2*/:
            case Protocol.TCP /*6*/:
            case Protocol.BBN_RCC_MON /*10*/:
                this.Temp1.setText(getResources().getString(R.string.ComprobandoRed) + ".. ");
                break;
            case Protocol.GGP /*3*/:
            case Service.ECHO /*7*/:
            case Service.USERS /*11*/:
                this.Temp1.setText(getResources().getString(R.string.ComprobandoRed) + "...");
                break;
            case Protocol.PUP /*12*/:
            case Protocol.CHAOS /*16*/:
                this.Temp1.setText(getResources().getString(R.string.AnalizandoRed) + "   ");
                break;
            case Service.DAYTIME /*13*/:
            case Service.QUOTE /*17*/:
                this.Temp1.setText(getResources().getString(R.string.AnalizandoRed) + ".  ");
                break;
            case Protocol.EMCON /*14*/:
            case Protocol.MUX /*18*/:
                this.Temp1.setText(getResources().getString(R.string.AnalizandoRed) + ".. ");
                break;
            case Protocol.XNET /*15*/:
            case Service.CHARGEN /*19*/:
                this.Temp1.setText(getResources().getString(R.string.AnalizandoRed) + "...");
                break;
            default:
                this.Temp1.setText(getResources().getString(R.string.Finalizando));
                break;
        }
        this.ContadorFirstScreen++;
    }

    public void MostrarVotar() {
        OnClickListener dialogClickListener = new OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                    case -3:
                        MainActivity.BD2.removeSettings();
                        MainActivity.BD2.insertSettings("3.9", 0);
                        FirstScreen.this.Start();
                        return;
                    case -2:
                        MainActivity.BD2.removeSettings();
                        MainActivity.BD2.insertSettings("3.9", 11);
                        FirstScreen.this.Start();
                        return;
                    case NbtException.CONNECTION_REFUSED /*-1*/:
                        Intent i = new Intent("android.intent.action.VIEW");
                        i.setData(Uri.parse("https://play.google.com/store/apps/details?id=lksystems.wifiintruder"));
                        FirstScreen.this.startActivity(i);
                        FirstScreen.this.Opinar = true;
                        return;
                    default:
                        return;
                }
            }
        };
        CharSequence styledText = Html.fromHtml(String.format(getResources().getString(R.string.TextoVotar), new Object[0]));
        CharSequence styledText2 = Html.fromHtml(String.format(getResources().getString(R.string.TituloVotar), new Object[0]));
        Builder builder = new Builder(this.MyContext);
        builder.setPositiveButton(getResources().getString(R.string.Yes), dialogClickListener).setTitle(styledText2).setIcon(R.drawable.icononotificacion).setPositiveButton(getResources().getString(R.string.VotarAhora), dialogClickListener).setNegativeButton(getResources().getString(R.string.VotarNunca), dialogClickListener).setNeutralButton(getResources().getString(R.string.VotarLuego), dialogClickListener).setCancelable(false).setMessage(styledText);
        builder.show();
    }

    public void MostrarNovedades() {
        OnClickListener dialogClickListener = new OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                    case NbtException.CONNECTION_REFUSED /*-1*/:
                        FirstScreen.this.Start();
                        return;
                    default:
                        return;
                }
            }
        };
        CharSequence styledText = Html.fromHtml(String.format(getResources().getString(R.string.Novedades20), new Object[0]));
        CharSequence styledText2 = Html.fromHtml(String.format(getResources().getString(R.string.Novedades), new Object[0]));
        Builder builder = new Builder(this.MyContext);
        builder.setPositiveButton(getResources().getString(R.string.Yes), dialogClickListener).setTitle(styledText2).setIcon(R.drawable.icononotificacion).setPositiveButton("OK", dialogClickListener).setCancelable(false).setMessage(styledText);
        builder.show();
    }
}
