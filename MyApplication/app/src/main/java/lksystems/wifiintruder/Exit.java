package lksystems.wifiintruder;

import android.app.Activity;
import android.content.Context;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Process;
import android.text.Html;
import android.view.KeyEvent;
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

public class Exit extends Activity {
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
        setContentView(R.layout.exit_screen);
        this.Temp1 = (TextView) findViewById(R.id.textViewTitulo1);
        this.Temp2 = (TextView) findViewById(R.id.textViewTitulo2);
        this.Temp3 = (TextView) findViewById(R.id.textViewRed);
        this.Temp4 = (TextView) findViewById(R.id.List);
        this.Temp5 = (TextView) findViewById(R.id.textViewRed2);
        this.Temp1.setText(getResources().getString(R.string.Exit1));
        this.Temp2.setText(getResources().getString(R.string.Exit2));
        this.Temp3.setText(getResources().getString(R.string.Exit3) + " ");
        this.Temp4.setText(Html.fromHtml(String.format(getResources().getString(R.string.Exit5), new Object[0])));
        this.Temp5.setText(getResources().getString(R.string.Exit4));
        AdView adView = new AdView(this);
        adView.setAdUnitId("ca-app-pub-2885006023541960/2348767733");
        adView.setAdSize(AdSize.SMART_BANNER);
        adView = (AdView) findViewById(R.id.adView);
        adView.loadAd(new Builder().build());
        final AdView finalAdView = adView;
        adView.setAdListener(new AdListener() {
            public void onAdLoaded() {
                int height = finalAdView.getHeight();
                RelativeLayout relativeLayout = new RelativeLayout(Exit.this.MyContext);
                ((RelativeLayout) Exit.this.findViewById(R.id.Todo2)).setPadding(0, 0, 0, height + 1);
            }
        });
    }

    protected void onStart() {
        super.onStart();
    }

    protected void onResume() {
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

    public void OnClickExit(View v) {
        finish();
        Process.killProcess(Process.myPid());
    }

    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (VERSION.SDK_INT < 5 && keyCode == 4 && event.getRepeatCount() == 0) {
            onBackPressed();
        }
        return super.onKeyDown(keyCode, event);
    }

    public void onBackPressed() {
        finish();
        Process.killProcess(Process.myPid());
    }
}
