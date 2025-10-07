package xyz.hexene.localvpn;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.content.DialogInterface;
import android.os.Bundle;

//Activity to be created as a base for display a Dialog as an alert when an application tries to access the Local Network
public class DialogDisplay extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dialog_display);

        showAlertDialog();
    }


    private void showAlertDialog(){
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Dialog title")
                .setMessage("Just to test it")
                .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                        DialogDisplay.super.finish();
                    }
                }).create();

        dialog.show();
    }
}